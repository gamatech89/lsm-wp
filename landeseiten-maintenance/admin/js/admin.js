/**
 * Landeseiten Maintenance - Admin JavaScript
 */

(function($) {
    'use strict';

    $(document).ready(function() {
        // Toggle functionality notification
        $('.lsm-toggle input[type="checkbox"]').on('change', function() {
            // Visual feedback that change was registered
            var $slider = $(this).siblings('.lsm-toggle-slider');
            $slider.css('opacity', '0.7');
            setTimeout(function() {
                $slider.css('opacity', '1');
            }, 200);
        });

        // Copy API key functionality
        $(document).on('click', '.lsm-copy-btn', function() {
            var $input = $(this).siblings('input');
            $input.select();
            document.execCommand('copy');
            
            var $btn = $(this);
            var originalText = $btn.text();
            $btn.text('Copied!');
            setTimeout(function() {
                $btn.text(originalText);
            }, 2000);
        });

        // Form validation feedback
        $('.lsm-input').on('focus', function() {
            $(this).parent().addClass('lsm-focused');
        }).on('blur', function() {
            $(this).parent().removeClass('lsm-focused');
        });

        // Regenerate API key
        $('#lsm-regenerate-key').on('click', function(e) {
            e.preventDefault();
            if (confirm('Are you sure you want to regenerate the API key? You will need to update it in your Landeseiten Dashboard.')) {
                // Generate a random 32-character key
                var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                var newKey = '';
                for (var i = 0; i < 32; i++) {
                    newKey += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                $('#lsm-api-key').val(newKey);
                // Highlight the save button
                $('#lsm-api-key-form button[type="submit"]').addClass('lsm-btn-highlight');
            }
        });

        // Show success message if API key was saved
        if (window.location.search.indexOf('api_key_saved=1') !== -1) {
            var $keyWrapper = $('.lsm-api-key-display');
            $keyWrapper.prepend('<div class="lsm-notice lsm-notice-success">API key saved successfully!</div>');
            // Remove the query parameter from URL
            window.history.replaceState({}, document.title, window.location.pathname + '?page=landeseiten-maintenance');
        }

        // Scroll to support form if hash is present
        if (window.location.hash === '#support-form') {
            setTimeout(function() {
                var $supportForm = $('#support-form');
                if ($supportForm.length) {
                    $('html, body').animate({
                        scrollTop: $supportForm.offset().top - 50
                    }, 500);
                    // Focus on first field
                    $supportForm.find('select, input').first().focus();
                }
            }, 300);
        }

        // Inline support form submission
        $('#lsm-inline-support-form').on('submit', function(e) {
            e.preventDefault();
            
            var $form = $(this);
            var $btn = $form.find('button[type="submit"]');
            var $btnText = $btn.find('.lsm-btn-text');
            var $btnLoading = $btn.find('.lsm-btn-loading');
            var $success = $('#lsm-support-success');
            
            // Show loading state
            $btnText.hide();
            $btnLoading.show();
            $btn.prop('disabled', true);
            
            // Get form data
            var formData = {
                action: 'lsm_submit_support',
                issue_type: $form.find('[name="issue_type"]').val(),
                subject: $form.find('[name="subject"]').val(),
                message: $form.find('[name="message"]').val(),
                user_email: $form.find('[name="user_email"]').val(),
                user_name: $form.find('[name="user_name"]').val(),
                site_url: $form.find('[name="site_url"]').val(),
                lsm_nonce: $form.find('[name="lsm_nonce"]').val()
            };
            
            $.ajax({
                url: typeof lsmSupport !== 'undefined' ? lsmSupport.ajaxUrl : ajaxurl,
                type: 'POST',
                data: formData,
                success: function(response) {
                    if (response.success) {
                        // Show success message
                        $form.find('.lsm-form-row, .lsm-form-group, .lsm-form-actions').hide();
                        $success.show();
                    } else {
                        alert(response.data ? response.data.message : 'An error occurred. Please try again.');
                    }
                },
                error: function() {
                    alert('An error occurred. Please try again.');
                },
                complete: function() {
                    $btnText.show();
                    $btnLoading.hide();
                    $btn.prop('disabled', false);
                }
            });
        });
    });

})(jQuery);
