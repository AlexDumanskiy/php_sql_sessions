<?php
/*
Revised code by Dominick Lee
Original code derived from "Essential PHP Security" by Chriss Shiflett
Last Modified 2/27/2017


CREATE TABLE sessions
(
    id varchar(32) NOT NULL,
    access int(10) unsigned,
    data text,
    PRIMARY KEY (id)
);
*/

require_once('database.php');

class Session
{
    private $db;

    public function __construct()
    {
        $this->db = new Database;
        session_set_save_handler(
            array($this, "_open"),
            array($this, "_close"),
            array($this, "_read"),
            array($this, "_write"),
            array($this, "_destroy"),
            array($this, "_gc")
        );

        session_start();
    }

    public function _open()
    {
        return !!$this->db;
    }

    public function _close()
    {
        return !!$this->db->close();
    }

    public function _read($id)
    {
        $this->db->query('SELECT data FROM sessions WHERE id = :id');
        $this->db->bind(':id', $id);
        if ($this->db->execute()) {
            if ($this->db->rowCount() > 0) {
                $row = $this->db->single();
                return $row['data'];
            }
        }
        return '';
    }

    public function _write($id, $data)
    {
        $access = time();
        $this->db->query('REPLACE INTO sessions VALUES (:id, :access, :data)');
        $this->db->bind(':id', $id);
        $this->db->bind(':access', $access);
        $this->db->bind(':data', $data);
        return !!$this->db->execute();
    }

    public function _destroy($id)
    {
        $this->db->query('DELETE FROM sessions WHERE id = :id');
        $this->db->bind(':id', $id);
        return !!$this->db->execute();
    }

    public function _gc($max)
    {
        $old = time() - $max;
        $this->db->query('DELETE FROM sessions WHERE access < :old');
        $this->db->bind(':old', $old);
        return !!$this->db->execute();
    }
}

$session = new Session();    //Start a new PHP MySQL session