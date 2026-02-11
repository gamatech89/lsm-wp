/**
 * Landeseiten Maintenance - Support Modal Script
 */

(function($) {
    'use strict';

    $(document).ready(function() {
        var $modal = $('#lsm-support-modal');
        var $form = $('#lsm-support-form');
        var $success = $('#lsm-support-success');

        // Open modal - admin bar button
        $(document).on('click', '#wp-admin-bar-lsm-support', function(e) {
            e.preventDefault();
            e.stopPropagation();
            openModal();
        });

        // Open modal - admin page Contact Support button
        $(document).on('click', '#lsm-open-support-modal', function(e) {
            e.preventDefault();
            e.stopPropagation();
            openModal();
        });

        // Close modal - multiple selectors
        $(document).on('click', '#lsm-support-modal .lsm-modal-close', function(e) {
            e.preventDefault();
            e.stopPropagation();
            closeModal();
        });

        $(document).on('click', '#lsm-support-modal .lsm-modal-cancel', function(e) {
            e.preventDefault();
            closeModal();
        });

        $(document).on('click', '#lsm-support-modal .lsm-modal-close-success', function(e) {
            e.preventDefault();
            closeModal();
        });

        // Close on overlay click
        $(document).on('click', '#lsm-support-modal .lsm-modal-overlay', function(e) {
            closeModal();
        });

        // Close on ESC
        $(document).on('keydown', function(e) {
            if (e.key === 'Escape' && $modal.is(':visible')) {
                closeModal();
            }
        });

        // Handle form submission
        $form.on('submit', function(e) {
            e.preventDefault();
            submitForm();
        });

        function openModal() {
            $modal.fadeIn(200);
            $('body').css('overflow', 'hidden');
            $form.show();
            $success.hide();
        }

        function closeModal() {
            $modal.fadeOut(200, function() {
                $form[0].reset();
                $form.show();
                $success.hide();
            });
            $('body').css('overflow', '');
        }

        function submitForm() {
            var $submitBtn = $form.find('button[type="submit"]');
            var $btnText = $submitBtn.find('.lsm-btn-text');
            var $btnLoading = $submitBtn.find('.lsm-btn-loading');

            // Show loading state
            $btnText.hide();
            $btnLoading.show();
            $submitBtn.prop('disabled', true);

            $.ajax({
                url: lsmSupport.ajaxUrl,
                type: 'POST',
                data: $form.serialize() + '&action=lsm_submit_support',
                success: function(response) {
                    if (response.success) {
                        $form.hide();
                        $success.fadeIn(200);
                    } else {
                        alert(response.data && response.data.message ? response.data.message : 'An error occurred. Please try again.');
                    }
                },
                error: function() {
                    alert('An error occurred. Please try again.');
                },
                complete: function() {
                    $btnText.show();
                    $btnLoading.hide();
                    $submitBtn.prop('disabled', false);
                }
            });
        }
    });

})(jQuery);
