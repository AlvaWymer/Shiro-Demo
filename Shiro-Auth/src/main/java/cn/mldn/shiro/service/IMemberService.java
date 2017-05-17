package cn.mldn.shiro.service;

import java.util.Set;

import cn.mldn.shiro.vo.Member;

public interface IMemberService {
	/**
	 * 列出一个用户对应的所有的权限数据信息
	 * @param mid 用户ID
	 * @return 所有的权限编号（唯一标记）
	 * @throws Exception SQL
	 */
	public Set<String> listActionsByMember(String mid) throws Exception ;
	/**
	 * 要进行用户对应的所有角色信息查询
	 * @param mid 用户的ID
	 * @return 所有的角色编号（唯一标记）
	 * @throws Exception SQL
	 */
	public Set<String> listRolesByMember(String mid) throws Exception ;
	
	/**
	 * 根据用户编号查找出一个用户的完整信息，如果为空将触发用户不存在的异常
	 * @param id 用户编号
	 * @return 如果可以查询到指定的用户数据以VO形式返回如果没有返回null
	 * @throws Exception SQL异常
	 */
	public Member get(String id) throws Exception ;
}
