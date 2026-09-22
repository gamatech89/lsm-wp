<?php

/**
 * The INSERT IGNORE lock.
 */
class HardeningLockTest extends HardeningTestCase {

    public function test_lock_is_taken_once_and_stores_the_time() {
        $this->assertTrue($this->h->acquire_lock());
        $this->assertSame($this->h->time, get_option('lsm_hardening_lock'));
        $this->assertFalse($this->h->acquire_lock());
    }

    public function test_release_frees_the_lock() {
        $this->h->acquire_lock();
        $this->h->release_lock();
        $this->assertFalse(get_option('lsm_hardening_lock'));
        $this->assertTrue($this->h->acquire_lock());
    }

    public function test_a_lock_of_exactly_180_seconds_is_still_held() {
        $this->h->acquire_lock();
        $this->h->time += 180;
        $this->assertFalse($this->h->acquire_lock());
    }

    public function test_a_lock_older_than_180_seconds_is_stale_and_taken_over() {
        $this->h->acquire_lock();
        $this->h->time += 181;
        $this->assertTrue($this->h->acquire_lock());
        $this->assertSame($this->h->time, get_option('lsm_hardening_lock'));
    }

    public function test_the_lock_is_not_the_state_option() {
        $this->h->acquire_lock();
        $this->assertFalse(get_option('lsm_hardening'));
    }
}
