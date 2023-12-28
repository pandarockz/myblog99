package com.myblog9.service.impl;

import com.myblog9.entity.Post;
import com.myblog9.exception.ResourceNotFound;
import com.myblog9.payload.PostDto;
import com.myblog9.payload.PostResponse;
import com.myblog9.repository.PostRepository;
import com.myblog9.service.PostService;
import com.myblog9.util.MainUtil;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class PostServiceImpl implements PostService {
    private static final Logger logger = LoggerFactory.getLogger(PostServiceImpl.class);
    private  PostRepository postRepo;

     private ModelMapper modelMapper;
    public PostServiceImpl(PostRepository postRepo , ModelMapper modelMapper) {
        this.postRepo = postRepo;
        this.modelMapper = modelMapper;
    }

    @Override
    public PostDto createPost(PostDto postDto) {

       Post post = mapToEntity(postDto);
        Post savedPost = postRepo.save(post);
        PostDto dto = mapToDto(savedPost);
        return dto;
    }

    @Override
    public void deletePostById(long id) {
      Post post =  postRepo.findById(id).orElseThrow(
                ()->new ResourceNotFound("Post Not Found with Id:"+id)
        );
      postRepo.deleteById(id);
    }

    @Override
    public PostDto getPostById(long id) {
        Post post = postRepo.findById(id).orElseThrow(
                ()-> new ResourceNotFound("Post not found with id:"+id)

        );
        return mapToDto(post);
    }

    @Override
    public PostDto updatePost(long id, PostDto postDto) {
        Post post = postRepo.findById(id).orElseThrow(
                ()-> new ResourceNotFound("Post not found with id:"+id)

        );

        post.setTitle(postDto.getTitle());
        post.setDescription(postDto.getDescription());
        post.setContent(postDto.getContent());

        Post savedPost = postRepo.save(post);

        PostDto dto = mapToDto(savedPost);
        return dto;
    }


    //USING STREAM API:-
    @Override
    public List<PostDto> getAllPosts() {
        List<Post> posts = postRepo.findAll();
        List<PostDto> dtos = posts.stream().map(post -> mapToDto(post)).collect(Collectors.toList());
        return dtos;
    }




                 // PAGINATION
    @Override
    public PostResponse getAllRecords(int pageNo, int pageSize, String sortBy, String sortDir) {
        Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name())?Sort.by(sortBy).ascending():Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(pageNo,pageSize,sort);
        Page<Post> pagePostObjects = postRepo.findAll(pageable);
       List<Post> posts = pagePostObjects.getContent();

        List<PostDto> dtos = posts.stream().map(post -> mapToDto(post)).collect(Collectors.toList());

        PostResponse response = new PostResponse();
        response.setDto(dtos);
        response.setPageNo((pagePostObjects.getNumber()));
        response.setTotalPages(pagePostObjects.getTotalPages());
        response.setLastPage(pagePostObjects.isLast());
        response.setPageSize((pagePostObjects.getSize()));
        return response;

    }

    Post mapToEntity(PostDto postDto){
       Post post = modelMapper.map(postDto, Post.class);
//        Post post = new Post();
//        post.setTitle(postDto.getTitle());
//        post.setDescription(postDto.getDescription());
//        post.setContent(postDto.getContent());
        return post;

    }
    PostDto mapToDto(Post savedpost){

        PostDto postDto = modelMapper.map(savedpost,PostDto.class);
//        PostDto postDto = new PostDto();
//        postDto.setId(savedpost.getId());
//        postDto.setTitle(savedpost.getTitle());
//        postDto.setDescription(savedpost.getDescription());
//        postDto.setContent(savedpost.getContent());
        return postDto;

    }
}
