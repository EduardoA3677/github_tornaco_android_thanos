.class public interface abstract annotation Llyiahf/vczjk/c94;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/annotation/Annotation;


# annotations
.annotation system Ldalvik/annotation/AnnotationDefault;
    value = .subannotation Llyiahf/vczjk/c94;
        as = Ljava/lang/Void;
        builder = Ljava/lang/Void;
        contentAs = Ljava/lang/Void;
        contentConverter = Llyiahf/vczjk/ep1;
        contentUsing = Llyiahf/vczjk/d94;
        converter = Llyiahf/vczjk/ep1;
        keyAs = Ljava/lang/Void;
        keyUsing = Llyiahf/vczjk/si4;
        using = Llyiahf/vczjk/d94;
    .end subannotation
.end annotation

.annotation runtime Ljava/lang/annotation/Retention;
    value = .enum Ljava/lang/annotation/RetentionPolicy;->RUNTIME:Ljava/lang/annotation/RetentionPolicy;
.end annotation


# virtual methods
.method public abstract as()Ljava/lang/Class;
.end method

.method public abstract builder()Ljava/lang/Class;
.end method

.method public abstract contentAs()Ljava/lang/Class;
.end method

.method public abstract contentConverter()Ljava/lang/Class;
.end method

.method public abstract contentUsing()Ljava/lang/Class;
.end method

.method public abstract converter()Ljava/lang/Class;
.end method

.method public abstract keyAs()Ljava/lang/Class;
.end method

.method public abstract keyUsing()Ljava/lang/Class;
.end method

.method public abstract using()Ljava/lang/Class;
.end method
