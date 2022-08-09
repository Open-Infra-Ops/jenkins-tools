# jenkins-tools工具

## 1.背景

​	在部署jenkins的时候，将jenkins的配置固化到数据盘，一旦盘遭遇损坏，将造成不可逆的影响，可以选择基于盘做数据备份和恢复，但是在jenkins服务迁移的时候，欠缺灵活性（因为需要共享同一块盘，或者基于盘进行复制），因此需要开发jenkins-tools工具来备份和恢复jenkins的相关配置。

## 2.需求

​	 使用jenkins-tools对jenkins的资源进行备份和恢复，其中资源包括但不局限于：插件，安全凭证，node， jobs，view，user，clouds，folder等资源。

​	备份： 在k8s中部署定时器服务， 对配置中的jenkins的网站，使用jenkins api接口进行用户名和密码认证，进行资源采集，再将采集资源通过git push的方式推到github上，资源保存地址：https://github.com/opensourceways/infra-jenkins。

​	恢复： 新建一个jenkins服务，配置系统管理员， 再从备份的资源保存地址中获取需要恢复域名的资源，使用jenkins api接口进行资源创建和恢复。

## 3.项目介绍

jenkins_obj:  是对jenkins api接口预演时，对单个job, view资源进行增、删、查、改等操作的工具，详细见[jenkins_obj](https://github.com/Open-Infra-Ops/jenkins-tools/tree/main/jenkins_obj)。

jenkins_bak_recover： 是对jenkins资源进行备份和恢复的工具，详细见[jenkins_bak_recover](https://github.com/Open-Infra-Ops/jenkins-tools/tree/main/jenkins_bak_recover)。





