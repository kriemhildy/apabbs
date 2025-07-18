//! Post review actions, error types, and moderation logic.
//!
//! This module defines the review workflow for posts, including allowed status transitions,
//! moderator/admin permissions, and the actions to take on post media during moderation.

use super::{Post, PostStatus, media};
use crate::{AppState, user::AccountRole};
use ReviewAction::*;
use ReviewError::*;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::{error::Error, fmt};
use uuid::Uuid;

/// Defines possible actions resulting from post review decisions.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ReviewAction {
    /// Decrypt and process encrypted media for public viewing
    PublishMedia,
    /// Delete encrypted media files that haven't been published
    DeleteEncryptedMedia,
    /// Delete media files from the public directory
    DeletePublishedMedia,
    /// Move published media back to encrypted state
    UnpublishMedia,
    /// Update post status without modifying media files
    NoAction,
}

/// Represents errors that can occur during post review.
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

/// Represents a post review action submitted by a moderator or admin.
#[derive(Serialize, Deserialize, Clone)]
pub struct PostReview {
    /// Session token of the user performing the review
    pub session_token: Uuid,
    /// New status to apply to the post
    pub status: PostStatus,
}

impl PostReview {
    /// Records a review action in the database to track moderation activity.
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
}

/// Determines the moderation action for a post review based on post state and user role.
pub fn determine_action(
    post: &Post,
    new_status: PostStatus,
    reviewer_role: AccountRole,
) -> Result<ReviewAction, ReviewError> {
    use PostStatus::*;

    match post.status {
        Pending => match new_status {
            Pending => Err(SameStatus),
            Processing => Err(ManualProcessing),
            Approved | Delisted => Ok(PublishMedia),
            Reported => Ok(NoAction),
            Rejected | Banned => Ok(DeleteEncryptedMedia),
        },

        Processing => Err(CurrentlyProcessing),

        Approved | Delisted => {
            if post.status == Approved && reviewer_role == AccountRole::Mod && !post.recent.unwrap()
            {
                return Err(RecentOnly);
            }
            match new_status {
                Pending => Err(ReturnToPending),
                Processing => Err(ManualProcessing),
                Approved | Delisted => Ok(NoAction),
                Reported => Ok(UnpublishMedia),
                Rejected | Banned => Ok(DeletePublishedMedia),
            }
        }

        Reported => {
            if reviewer_role != AccountRole::Admin {
                return Err(AdminOnly);
            }
            match new_status {
                Pending => Err(ReturnToPending),
                Processing => Err(ManualProcessing),
                Approved | Delisted => Ok(PublishMedia),
                Rejected | Banned => Ok(DeleteEncryptedMedia),
                Reported => Err(SameStatus),
            }
        }

        Rejected | Banned => Err(RejectedOrBanned),
    }
}

/// Processes a review action and optionally returns a background task.
pub async fn process_action(
    state: &AppState,
    post: &Post,
    status: PostStatus,
    action: ReviewAction,
) -> Result<Option<BoxFuture<'static, ()>>, Box<dyn Error + Send + Sync>> {
    if post.media_category.is_none() {
        return Ok(None);
    }

    let background_task: Option<BoxFuture<'static, ()>> = match action {
        PublishMedia => Some(Box::pin(publish_media_task(
            state.clone(),
            post.clone(),
            status,
        ))),
        DeleteEncryptedMedia => {
            media::delete_upload_key_dir(&post.key).await?;
            None
        }
        DeletePublishedMedia => {
            media::delete_media_key_dir(&post.key).await?;
            None
        }
        UnpublishMedia => Some(Box::pin(unpublish_media_task(
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
        let mut tx = state.db.begin().await?;
        media::publish_media(&mut tx, &post).await?;
        let post = post.update_status(&mut tx, status).await?;
        media::delete_upload_key_dir(&post.key)
            .await
            .map_err(|e| format!("delete upload directory: {e}"))?;
        tx.commit().await?;
        state.sender.send(post.clone()).ok();
        tracing::info!("Media publication task completed for post {}", post.id);
        Ok(())
    }
    .await;

    if let Err(e) = result {
        tracing::error!("Error in publish_media_task: {e}");
    }
}

/// Background task for unpublishing media and updating post status.
pub async fn unpublish_media_task(state: AppState, post: Post, status: PostStatus) {
    let result: Result<(), Box<dyn Error + Send + Sync>> = async {
        tracing::info!(
            "Unpublishing media for post {} with status {:?}",
            post.id,
            status
        );
        let mut tx = state.db.begin().await?;
        media::unpublish_media(&post)
            .await
            .map_err(|e| format!("unpublish media: {e}"))?;
        let post = post.update_status(&mut tx, status).await?;
        tx.commit().await?;
        state.sender.send(post.clone()).ok();
        tracing::info!("Unpublish task completed for post {}", post.id);
        Ok(())
    }
    .await;

    if let Err(e) = result {
        tracing::error!("Error in unpublish_media_task: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests post status transitions and review actions for different user roles.
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
            determine_action(&post, PostStatus::Approved, AccountRole::Admin),
            Ok(ReviewAction::PublishMedia)
        );

        // Case 2: Mod trying to modify a reported post (should fail)
        let reported_post = Post {
            status: PostStatus::Reported,
            ..Post::default()
        };
        assert_eq!(
            determine_action(&reported_post, PostStatus::Approved, AccountRole::Mod),
            Err(ReviewError::AdminOnly)
        );

        // Case 3: Trying to modify a banned post (should fail)
        let banned_post = Post {
            status: PostStatus::Banned,
            ..Post::default()
        };
        assert_eq!(
            determine_action(&banned_post, PostStatus::Approved, AccountRole::Admin),
            Err(ReviewError::RejectedOrBanned)
        );

        // Case 4: Mod trying to report an approved post (valid action)
        let approved_post = Post {
            status: PostStatus::Approved,
            recent: Some(true),
            ..Post::default()
        };
        assert_eq!(
            determine_action(&approved_post, PostStatus::Reported, AccountRole::Mod),
            Ok(ReviewAction::UnpublishMedia)
        );

        // Case 5: Mod trying to modify a non-recent approved post (should fail)
        let old_post = Post {
            status: PostStatus::Approved,
            recent: Some(false),
            ..Post::default()
        };
        assert_eq!(
            determine_action(&old_post, PostStatus::Delisted, AccountRole::Mod),
            Err(ReviewError::RecentOnly)
        );
    }
}
