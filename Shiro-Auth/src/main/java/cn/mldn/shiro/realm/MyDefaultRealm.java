package cn.mldn.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import cn.mldn.shiro.service.IMemberService;
import cn.mldn.shiro.service.impl.MemberServiceImpl;
import cn.mldn.shiro.vo.Member;

public class MyDefaultRealm extends AuthorizingRealm {
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		System.out.println("++++++++++++++ 2、进行授权操作处理 ++++++++++++++");
		// 该操作的主要目的是取得授权信息，说的直白一点就是角色和权限数据
		SimpleAuthorizationInfo auth = new SimpleAuthorizationInfo() ;
		// 执行到此方法的时候一定是已经进行过用户认证处理了（用户名和密码一定是正确的）
		String mid = (String) principals.getPrimaryPrincipal() ;	// 取得用户名
		try {
			// 存在了用户编号之后就意味着可以进行用户的角色或权限数据查询
			IMemberService memberService = new MemberServiceImpl();
			auth.setRoles(memberService.listRolesByMember(mid)); 	// 保存所有的角色
			auth.setStringPermissions(memberService.listActionsByMember(mid)); // 保存所有的权限
		} catch (Exception e) {
			e.printStackTrace();
		}
		return auth ;
	}
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		System.out.println("============== 1、进行认证操作处理 ==============");
		// 用户的认证信息一定要通过IMemberService获取
		IMemberService memberService = new MemberServiceImpl();
		String userid = token.getPrincipal().toString(); // 用户名
		// 定义需要进行返回的操作数据信息项
		SimpleAuthenticationInfo auth = new SimpleAuthenticationInfo(
				token.getPrincipal(), token.getCredentials(), "memberRealm");
		try {
			// 取得用户名之后就需要通过业务层获取用户对象以确定改用户名是否可用
			Member member = memberService.get(userid); // 通过用户名获取用户信息
			if (member == null) { // 表示该用户信息不存在，不存在则应该抛出一个异常
				throw new UnknownAccountException("搞什么搞，用户名不存在！");
			}
			// 用户名如果存在了，那么就需要确定密码是否正确
			String password = new String((char[]) token.getCredentials());
			if (!password.equals(member.getPassword())) { // 密码验证
				throw new IncorrectCredentialsException("密码都记不住，去死吧！");
			}
			// 随后还需要考虑用户被锁定的问题
			if (member.getLocked().equals(1)) { // 1表示非0，非0就是true
				throw new LockedAccountException("被锁了，求解锁去吧！");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return auth;
	}


}
