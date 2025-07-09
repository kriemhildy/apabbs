//! Post review actions, error types, and moderation logic.
//!
//! This module defines the review workflow for posts, including allowed status transitions,
//! moderator/admin permissions, and the actions to take on post media during moderation.

use super::{Post, PostStatus};
use crate::{
    AppState,
    user::AccountRole,
    utils::{begin_transaction, commit_transaction, send_to_websocket},
};
use ReviewAction::*;
use ReviewError::*;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::{error::Error, fmt};
use uuid::Uuid;

/// Defines possible actions resulting from post review decisions.
///
/// Each action represents a specific operation to perform on a post's media
/// or status during the moderation workflow.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ReviewAction {
    /// Decrypt and process encrypted media for public viewing
    PublishMedia,
    /// Delete encrypted media files that haven't been published
    DeleteEncryptedMedia,
    /// Delete media files from the public directory
    DeletePublishedMedia,
    /// Move published media back to encrypted pending state
    ReencryptMedia,
    /// Update post status without modifying media files
    NoAction,
}

/// Represents errors that can occur during post review
///
/// These errors correspond to business rules that restrict
/// which status transitions are allowed and by which roles.
#[derive(PartialEq, Debug)]
pub enum ReviewError {
    /// Attempted to change post to its current status
    SameStatus,
    /// Cannot revert a post back to pending status
    ReturnToPending,
    /// Operation restricted to administrator role
    AdminOnly,
    /// Cannot modify posts with final status (rejected/banned)
    RejectedOrBanned,
    /// Moderators can only modify recent posts
    RecentOnly,
    /// Cannot modify a post that's currently being processed
    CurrentlyProcessing,
    /// Cannot manually set a post to processing status
    ManualProcessing,
}

impl fmt::Display for ReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SameStatus => write!(f, "Attempted to change post to its current status."),
            ReturnToPending => write!(f, "Cannot revert a post back to pending status."),
            AdminOnly => write!(f, "Operation restricted to administrator role."),
            RejectedOrBanned => write!(f, "Cannot modify rejected or banned posts."),
            RecentOnly => write!(f, "Moderators can only modify recent posts."),
            CurrentlyProcessing => write!(f, "Cannot modify a post that's being processed."),
            ManualProcessing => write!(f, "Cannot manually set a post to processing status."),
        }
    }
}

/// Represents a post review action submitted by a moderator or admin
///
/// Contains the reviewer's session token and the proposed new status for the post.
/// Used to process moderation decisions through the review workflow.
#[derive(Serialize, Deserialize, Clone)]
pub struct PostReview {
    /// Session token of the user performing the review
    pub session_token: Uuid,

    /// New status to apply to the post
    pub status: PostStatus,
}

impl PostReview {
    /// Records a review action in the database.
    ///
    /// Creates an entry in the reviews table to track moderation activity.
    pub async fn insert(
        &self,
        tx: &mut PgConnection,
        account_id: i32,
        post_id: i32,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        sqlx::query("INSERT INTO reviews (account_id, post_id, status) VALUES ($1, $2, $3)")
            .bind(account_id)
            .bind(post_id)
            .bind(self.status)
            .execute(&mut *tx)
            .await
            .map(|_| ())
            .map_err(|e| format!("insert review: {e}").into())
    }

    /// Determines the moderation action for a post review based on post state and user role.
    ///
    /// Returns an error if the action is not allowed by business rules.
    pub fn determine_action(
        post: &Post,
        new_status: PostStatus,
        reviewer_role: AccountRole,
    ) -> Result<ReviewAction, ReviewError> {
        use AccountRole::*;
        use PostStatus::*;

        match post.status {
            // Rules for posts in Pending status
            Pending => match new_status {
                Pending => Err(SameStatus),                    // No change needed
                Processing => Err(ManualProcessing),           // Processing is set automatically
                Approved | Delisted => Ok(PublishMedia), // Approve: decrypt media for public view
                Reported => Ok(NoAction),                // Just change status, no media action
                Rejected | Banned => Ok(DeleteEncryptedMedia), // Delete encrypted media
            },

            // Posts being processed can't be changed until processing completes
            Processing => Err(CurrentlyProcessing),

            // Rules for already approved or delisted posts
            Approved | Delisted => {
                // Mods can only change recent posts
                if post.status == Approved && reviewer_role == Mod && !post.recent.unwrap() {
                    return Err(RecentOnly);
                }

                match new_status {
                    Pending => Err(ReturnToPending),     // Can't go backwards to pending
                    Processing => Err(ManualProcessing), // Processing is set automatically
                    Approved | Delisted => Ok(NoAction), // Just status change, no media action
                    Reported => {
                        // Usually only mods report for admin review, but admins are not unable
                        Ok(ReencryptMedia)
                    }
                    Rejected | Banned => Ok(DeletePublishedMedia), // Delete the published media
                }
            }

            // Rules for reported posts
            Reported => {
                // Only admins can review reported posts
                if reviewer_role != Admin {
                    return Err(AdminOnly);
                }

                match new_status {
                    Pending => Err(ReturnToPending),     // Can't go backwards to pending
                    Processing => Err(ManualProcessing), // Processing is set automatically
                    Approved | Delisted => Ok(PublishMedia), // Approve: decrypt for public view
                    Rejected | Banned => Ok(DeleteEncryptedMedia), // Delete the encrypted media
                    Reported => Err(SameStatus),         // No change needed
                }
            }

            // Rejected or banned posts are final and can't be changed
            Rejected | Banned => Err(RejectedOrBanned),
        }
    }

    /// Process a review action and optionally return a background task future.
    pub async fn process_action(
        state: &AppState,
        post: &Post,
        status: PostStatus,
        action: ReviewAction,
    ) -> Result<Option<BoxFuture<'static, ()>>, Box<dyn Error + Send + Sync>> {
        if post.media_category.is_none() {
            return Ok(None); // No media to process
        }

        let background_task: Option<BoxFuture<'static, ()>> = match action {
            PublishMedia => {
                // Create background task for media publication
                Some(Box::pin(PostReview::publish_media_task(
                    state.clone(),
                    post.clone(),
                    status,
                )))
            }

            DeleteEncryptedMedia => {
                // Delete the encrypted media file
                PostReview::delete_upload_key_dir(&post.key).await?;
                None
            }

            // Handle media deletion
            DeletePublishedMedia => {
                PostReview::delete_media_key_dir(&post.key).await?;
                None
            }

            // Handle media re-encryption
            ReencryptMedia => Some(Box::pin(PostReview::reencrypt_media_task(
                state.clone(),
                post.clone(),
                status,
            ))),

            NoAction => None,
        };

        Ok(background_task)
    }

    // =========================
    // Background Media Tasks
    // =========================

    /// Background task for publishing media and updating post status.
    pub async fn publish_media_task(state: AppState, post: Post, status: PostStatus) {
        let result: Result<(), Box<dyn Error + Send + Sync>> = async {
            tracing::info!("Publishing media for post {}", post.id,);
            let mut tx = begin_transaction(&state.db).await?;

            // Attempt media publication
            PostReview::publish_media(&mut tx, &post).await?;

            // Update post status
            let post = post.update_status(&mut tx, status).await?;

            // Delete the upload key directory after publishing
            PostReview::delete_upload_key_dir(&post.key)
                .await
                .map_err(|e| format!("delete upload directory: {e}"))?;

            commit_transaction(tx).await?;

            // Notify clients
            send_to_websocket(&state.sender, post.clone());

            tracing::info!("Media publication task completed for post {}", post.id);
            Ok(())
        }
        .await;

        if let Err(e) = result {
            tracing::error!("Error in publish_media_task: {e}");
        }
    }

    /// Background task for re-encrypting media and updating post status.
    pub async fn reencrypt_media_task(state: AppState, post: Post, status: PostStatus) {
        let result: Result<(), Box<dyn Error + Send + Sync>> = async {
            tracing::info!(
                "Re-encrypting media for post {} with status {:?}",
                post.id,
                status
            );
            let mut tx = begin_transaction(&state.db).await?;

            // Attempt media re-encryption
            post.reencrypt_media_file()
                .await
                .map_err(|e| format!("re-encrypt media: {e}"))?;

            // Update post status
            let post = post.update_status(&mut tx, status).await?;

            commit_transaction(tx).await?;

            // Notify clients
            send_to_websocket(&state.sender, post.clone());

            tracing::info!("Re-encryption task completed for post {}", post.id);
            Ok(())
        }
        .await;

        if let Err(e) = result {
            tracing::error!("Error in reencrypt_media_task: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests post status transitions and review actions for different user roles.
    #[tokio::test]
    async fn review_action_permissions() {
        // Create a post with defaults, only setting what we need for this test
        // PostStatus::Pending is already the default
        let post = Post {
            key: String::from("testkey"),
            ..Post::default()
        };

        // Case 1: Admin approving a pending post
        assert_eq!(
            PostReview::determine_action(&post, PostStatus::Approved, AccountRole::Admin),
            Ok(ReviewAction::PublishMedia)
        );

        // Case 2: Mod trying to modify a reported post (should fail)
        let reported_post = Post {
            status: PostStatus::Reported,
            ..Post::default()
        };
        assert_eq!(
            PostReview::determine_action(&reported_post, PostStatus::Approved, AccountRole::Mod),
            Err(ReviewError::AdminOnly)
        );

        // Case 3: Trying to modify a banned post (should fail)
        let banned_post = Post {
            status: PostStatus::Banned,
            ..Post::default()
        };
        assert_eq!(
            PostReview::determine_action(&banned_post, PostStatus::Approved, AccountRole::Admin),
            Err(ReviewError::RejectedOrBanned)
        );

        // Case 4: Mod trying to report an approved post (valid action)
        let approved_post = Post {
            status: PostStatus::Approved,
            recent: Some(true),
            ..Post::default()
        };
        assert_eq!(
            PostReview::determine_action(&approved_post, PostStatus::Reported, AccountRole::Mod),
            Ok(ReviewAction::ReencryptMedia)
        );

        // Case 5: Mod trying to modify a non-recent approved post (should fail)
        let old_post = Post {
            status: PostStatus::Approved,
            recent: Some(false),
            ..Post::default()
        };
        assert_eq!(
            PostReview::determine_action(&old_post, PostStatus::Delisted, AccountRole::Mod),
            Err(ReviewError::RecentOnly)
        );
    }
}
