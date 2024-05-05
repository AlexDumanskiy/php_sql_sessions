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

class PDOSessionHandler implements SessionHandlerInterface, SessionUpdateTimestampHandlerInterface
{
    private Database $db;

    public function __construct()
    {
        $this->db = new Database;
        return session_set_save_handler(
            array($this, "open"),
            array($this, "close"),
            array($this, "read"),
            array($this, "write"),
            array($this, "destroy"),
            array($this, "gc")
        );
    }

    public function open($path, $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        $this->db->close();
        return true;
    }

    public function read($id): string|false
    {
        $this->db->query('SELECT data FROM sessions WHERE id = :id');
        $this->db->bind(':id', $id);
        if ($this->db->execute()) {
            if ($this->db->rowCount() > 0) {
                $row = $this->db->single();
                return $row['data'];
            }
        }
        return false;
    }

    #[ReturnTypeWillChange] public function write($id, $data): bool
    {
        $access = time();
        $this->db->query('REPLACE INTO sessions VALUES (:id, :access, :data)');
        $this->db->bind(':id', $id);
        $this->db->bind(':access', $access);
        $this->db->bind(':data', $data);
        return !!$this->db->execute();
    }

    #[ReturnTypeWillChange] public function destroy($id): bool
    {
        $this->db->query('DELETE FROM sessions WHERE id = :id');
        $this->db->bind(':id', $id);
        return !!$this->db->execute();
    }

    #[ReturnTypeWillChange] public function gc($max_lifetime): bool
    {
        $old = time() - $max_lifetime;
        $this->db->query('DELETE FROM sessions WHERE access < :old');
        $this->db->bind(':old', $old);
        return !!$this->db->execute();
    }

    #[ReturnTypeWillChange] public function validateId(string $id): bool
    {
        $this->db->query('SELECT count(id) AS count FROM sessions WHERE id = :id');
        $this->db->bind(':id', $id);
        $this->db->execute();
        $row = $this->db->single();
        return ($row['count'] == 1);
    }

    #[ReturnTypeWillChange] public function updateTimestamp(string $id, string $data): void
    {
        $access = time();
        $this->db->query('UPDATE sessions SET access = :access WHERE id = :id)');
        $this->db->bind(':id', $id);
        $this->db->bind(':access', $access);
        $this->db->execute();
    }
}

$session = new PDOSessionHandler();