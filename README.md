# mock-4.1解析笔记

```
Something I hope you know before go into the coding~
First, please watch or star this repo, I'll be more happy if you follow me.
Bug report, questions and discussion are welcome, you can post an issue or pull a request.
```

## 简介

```
Mock is a simple program that will build source RPMs inside a chroot. It doesn't do anything fancy other than populating a chroot with the contents specified by a configuration file, then build any input SRPM(s) in that chroot.
```

* 官方仓库 : <https://github.com/rpm-software-management/mock/>
* 官方文档 : <https://rpm-software-management.github.io/mock/>
* man手册  : <https://www.mankier.com/1/mock>

## 闪电入门

```
$ mock -r rocky-8-x86_64 package.src.rpm
...
Finish: rpmbuild packagei-1.98-1.fc35.src.rpm
Finish: build phase for package-1.98-1.fc35.src.rpm
INFO: Done(package.src.rpm) Config(fedora-35-x86_64) 2 minutes 14 seconds
INFO: Results and/or logs in: /var/lib/mock/fedora-35-x86_64/result
$  ls /var/lib/mock/fedora-35-x86_64/result
build.log  package-1.98-1.fc35.noarch.rpm  package-1.98-1.fc35.src.rpm  hw_info.log  installed_pkgs.log  root.log  state.log

$ mock -r centos-stream+epel-9-s390x package.src.rpm
...
$ mock -r alma+epel-8-x86_64 package.src.rpm
...
```

## 目录

* [mock玩耍指南](docs/mock玩耍指南.md)
    * [知己知彼](docs/mock玩耍指南/知己知彼.md)
    * [帮助信息](docs/mock玩耍指南/帮助信息.md)
    * [玩起来](docs/mock玩耍指南/玩起来.md)
    * [捕获mock构建执行流](docs/mock玩耍指南/捕获mock构建执行流.md)
    * [入口解析](docs/mock玩耍指南/入口解析.md)
    * [为什么需要bootstrap chroot](docs/mock玩耍指南/为什么需要bootstrap_chroot.md)
    * [如何在不同构建阶段添加hook](docs/mock玩耍指南/如何在不同构建阶段添加hook.md)



















---
