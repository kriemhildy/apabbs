//! Post review actions, error types, and moderation logic.
//!
//! This module defines the review workflow for posts, including allowed status transitions,
//! moderator/admin permissions, and the actions to take on post media during moderation.

use super::Post;
use super::PostStatus;
use crate::user::AccountRole;
use sqlx::PgConnection;
use uuid::Uuid;

/// Defines possible actions resulting from post review decisions.
///
/// Each action represents a specific operation to perform on a post's media
/// or status during the moderation workflow.
#[derive(PartialEq, Debug)]
pub enum ReviewAction {
    /// Decrypt and process encrypted media for public viewing
    DecryptMedia,
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
    /// Operation restricted to moderator role
    ModOnly,
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

/// Represents a post review action submitted by a moderator or admin
///
/// Contains the reviewer's session token and the proposed new status for the post.
/// Used to process moderation decisions through the review workflow.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
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
    ///
    /// # Parameters
    /// - `tx`: Database transaction (mutable reference)
    /// - `account_id`: ID of the account performing the review
    /// - `post_id`: ID of the post being reviewed
    pub async fn insert(&self, tx: &mut PgConnection, account_id: i32, post_id: i32) {
        sqlx::query("INSERT INTO reviews (account_id, post_id, status) VALUES ($1, $2, $3)")
            .bind(account_id)
            .bind(post_id)
            .bind(self.status)
            .execute(&mut *tx)
            .await
            .expect("inserts");
    }

    /// Determines what action should be taken for a review based on post state and user role.
    ///
    /// Implements the business rules that govern post moderation:
    /// - Which transitions between post statuses are allowed
    /// - Which roles can perform which actions
    /// - What should happen to media files during each transition
    ///
    /// # Parameters
    /// - `post`: The post being reviewed
    /// - `reviewer_role`: Role of the user performing the review
    ///
    /// # Returns
    /// - `Ok(ReviewAction)` if the action is allowed
    /// - `Err(ReviewError)` if the action is not allowed
    pub fn determine_action(
        &self,
        post: &Post,
        reviewer_role: &AccountRole,
    ) -> Result<ReviewAction, ReviewError> {
        use AccountRole::*;
        use PostStatus::*;
        use ReviewAction::*;
        use ReviewError::*;

        match post.status {
            // Rules for posts in Pending status
            Pending => match self.status {
                Pending => Err(SameStatus),                    // No change needed
                Processing => Err(ManualProcessing),           // Processing is set automatically
                Approved | Delisted => Ok(DecryptMedia), // Approve: decrypt media for public view
                Reported => Ok(NoAction),                // Just change status, no media action
                Rejected | Banned => Ok(DeleteEncryptedMedia), // Delete encrypted media
            },

            // Posts being processed can't be changed until processing completes
            Processing => Err(CurrentlyProcessing),

            // Rules for already approved or delisted posts
            Approved | Delisted => {
                // Mods can only change recent posts
                if post.status == Approved && *reviewer_role == Mod && !post.recent.unwrap() {
                    return Err(RecentOnly);
                }

                match self.status {
                    Pending => Err(ReturnToPending),     // Can't go backwards to pending
                    Processing => Err(ManualProcessing), // Processing is set automatically
                    Approved | Delisted => Ok(NoAction), // Just status change, no media action
                    Reported => {
                        // Only mods can report posts
                        if *reviewer_role != Mod {
                            return Err(ModOnly);
                        }
                        // When reporting, re-encrypt the media for admin review
                        Ok(ReencryptMedia)
                    }
                    Rejected | Banned => Ok(DeletePublishedMedia), // Delete the published media
                }
            }

            // Rules for reported posts
            Reported => {
                // Only admins can review reported posts
                if *reviewer_role != Admin {
                    return Err(AdminOnly);
                }

                match self.status {
                    Pending => Err(ReturnToPending),     // Can't go backwards to pending
                    Processing => Err(ManualProcessing), // Processing is set automatically
                    Approved | Delisted => Ok(DecryptMedia), // Approve: decrypt for public view
                    Rejected | Banned => Ok(DeleteEncryptedMedia), // Delete the encrypted media
                    Reported => Err(SameStatus),         // No change needed
                }
            }

            // Rejected or banned posts are final and can't be changed
            Rejected | Banned => Err(RejectedOrBanned),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests post status transitions and review actions for different user roles
    #[tokio::test]
    async fn review_action_permissions() {
        // Create a post with defaults, only setting what we need for this test
        // PostStatus::Pending is already the default
        let post = Post {
            id: 1,
            key: String::from("testkey"),
            ..Default::default()
        };

        // Case 1: Admin approving a pending post
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Approved,
        };
        assert_eq!(
            review.determine_action(&post, &AccountRole::Admin),
            Ok(ReviewAction::DecryptMedia)
        );

        // Case 2: Mod trying to modify a reported post (should fail)
        let reported_post = Post {
            status: PostStatus::Reported,
            ..Default::default()
        };
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Approved,
        };
        assert_eq!(
            review.determine_action(&reported_post, &AccountRole::Mod),
            Err(ReviewError::AdminOnly)
        );

        // Case 3: Trying to modify a banned post (should fail)
        let banned_post = Post {
            status: PostStatus::Banned,
            ..Default::default()
        };
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Approved,
        };
        assert_eq!(
            review.determine_action(&banned_post, &AccountRole::Admin),
            Err(ReviewError::RejectedOrBanned)
        );

        // Case 4: Mod trying to report an approved post (valid action)
        let approved_post = Post {
            status: PostStatus::Approved,
            recent: Some(true),
            ..Default::default()
        };
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Reported,
        };
        assert_eq!(
            review.determine_action(&approved_post, &AccountRole::Mod),
            Ok(ReviewAction::ReencryptMedia)
        );

        // Case 5: Mod trying to modify a non-recent approved post (should fail)
        let old_post = Post {
            status: PostStatus::Approved,
            recent: Some(false),
            ..Default::default()
        };
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Delisted,
        };
        assert_eq!(
            review.determine_action(&old_post, &AccountRole::Mod),
            Err(ReviewError::RecentOnly)
        );
    }
}
