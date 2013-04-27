drop table if exists users;
drop table if exists nodes;
drop table if exists pools;
drop table if exists poolnodes;
drop table if exists vips;
drop table if exists settings;
drop table if exists pooltypes;

create table users (
    id integer primary key autoincrement,
    username string unique not null,
    password string not null,
    realname string not null,
    email string not null
);

create table settings (
    id integer primary key autoincrement,
    skey string not null,
    sval string not null,
    unique (skey, sval)
);

create table interfaces (
    id integer primary key autoincrement,
    iname string not null unique
);

create table vrrp (
    id integer primary key autoincrement,
    address string nog null unique,
    interface integer not null references interfaces(id) on update cascade on delete restrict
);

create table nodes (
    id integer primary key autoincrement,
    description string not null,
    ip string not null,
    port integer not null,
    owner integer not null default 1 references users(id) on update cascade on delete set default,
    unique (ip, port, owner)
);

create table pooltypes (
    id integer primary key autoincrement,
    typename string not null,
    typeconf string not null,
    unique (typename),
    unique (typeconf)
);

insert into pooltypes (typename, typeconf) values ('Natted', 'NAT');
insert into pooltypes (typename, typeconf) values ('Direct Routing', 'DR');
insert into pooltypes (typename, typeconf) values ('Tunneled', 'TUN');

create table pools (
    id integer primary key autoincrement,
    poolname string not null,
    pooltype integer not null references pooltypes(id) on update cascade on delete cascade,
    owner integer not null default 1 references users(id) on update cascade on delete set default,
    unique (poolname, owner)
);

create table poolnodes (
    id integer primary key autoincrement,
    node integer not null references nodes(id) on update cascade on delete restrict,
    pool integer not null references pools(id) on update cascade on delete cascade,
    owner integer not null default 1 references users(id) on update cascade on delete set default,
    unique (node, pool, owner)
);

create table vips (
    id integer primary key autoincrement,
    ip string not null,
    port string not null,
    pool integer not null references pools(id) on update cascade on delete restrict,
    owner integer not null default 1 references users(id) on update cascade on delete set default,
    interface integer not null references interfaces(id) on update cascade on delete restrict,
    unique (ip, port)
);
