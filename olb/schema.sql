drop table if exists users;
drop table if exists realservers;
drop table if exists pools;
drop table if exists poolnodes;
drop table if exists vips;

create table users (
    id integer primary key autoincrement,
    username string primary key not null,
    password string not null,
    realname string not null,
    email string not null
);

create table realservers (
    id integer primary key autoincrement,
    ip string not null,
    port integer not null,
    owner integer not null references users(id),
    primary key (ip, port, owner),
);

create table pools (
    id integer primary key autoincrement,
    poolname string not null,
    owner integer not null references users(id),
    primary key (poolname, owner)
);

create table poolnodes (
    id integer primary key autoincrement,
    node integer not null references realservers(id),
    pool integer not null references pools(id),
    owner integer not null references users(id)
    primary key (node, pool, owner)
);

create table vips (
    id integer primary key autoincrement,
    ip string not null,
    port string not null,
    pool integer not null references pools(id),
    owner integer not null references users(id),
    primary key (ip, port)
);
