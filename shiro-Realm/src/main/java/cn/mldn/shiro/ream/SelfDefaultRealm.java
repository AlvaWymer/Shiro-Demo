package cn.mldn.shiro.ream;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.Realm;

public class SelfDefaultRealm implements Realm {

	/**
	 * * 获取用户的认证处理信息 
	 * * @param token 用户的认证数据（用户名、认证数据） 
	 * * @return 认证结果 
	 * * @throws
	 * AuthenticationException 认证异常
	 */
	// 整个的认证的处理过程就是自定义了一个新的用户名：admin/hello，而后判断用户名或密码是否正确
	@Override
	public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// 如果要想进行用户信息的检测，则需要取得用户输入的用户名和密码数据
		String userid = (String) token.getPrincipal(); // 取得用户名
		// !!!!!!!!!!!!!!!!注意：此时有坑！！！！！！！！！！
		// 在进行密码数据保存的时候，它不是按照字符串存储的而是按照字符数组保存的
		String password = new String((char[]) token.getCredentials()); // 取得密码

		// 进行具体的信息判断，对于之前的判断有两类错误：
		if (!"admin".equals(userid)) { // 存在的用户名
			// 一旦抛出了异常，那么此时的操作就表示该方法已经结束了
			throw new UnknownAccountException("对不起，此用户信息未注册！");
		}
		if (!"hello".equals(password)) { // 登录失败
			throw new IncorrectCredentialsException("错误的用户名或密码！");
		}
		// 如果以上两个的处理过程之中没有抛出异常，那么就应该表示登录成功
		return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), this.getName());
	}

	/**
	 * * 所有的项目都一定会存在有认证与授权的处理操作，那么依靠Realm名字来区分不同的应用 
	 * * @return
	 * 你自己随便写一个就行了，因为这只是一个程序让用户自己看的标记
	 */
	@Override
	public String getName() {
		return "shiro-realm";
	}

	/**
	 * * 判断当前使用的认证的标记类型是否为指定的标记类型 
	 * * @param token 用户的自己输入的认证信息（用户、密码或证书）
	 * * @return 为特定的用户名或密码的标记类型返回true
	 */
	@Override
	public boolean supports(AuthenticationToken token) {
		return token instanceof UsernamePasswordToken; // 现在只是使用一个简单的用户名和密码检测
	}

}
