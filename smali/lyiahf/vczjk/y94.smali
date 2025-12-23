.class public interface abstract annotation Llyiahf/vczjk/y94;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/annotation/Annotation;


# annotations
.annotation system Ldalvik/annotation/AnnotationDefault;
    value = .subannotation Llyiahf/vczjk/y94;
        property = "@id"
        resolver = Llyiahf/vczjk/so8;
        scope = Ljava/lang/Object;
    .end subannotation
.end annotation

.annotation runtime Ljava/lang/annotation/Retention;
    value = .enum Ljava/lang/annotation/RetentionPolicy;->RUNTIME:Ljava/lang/annotation/RetentionPolicy;
.end annotation


# virtual methods
.method public abstract generator()Ljava/lang/Class;
.end method

.method public abstract property()Ljava/lang/String;
.end method

.method public abstract resolver()Ljava/lang/Class;
.end method

.method public abstract scope()Ljava/lang/Class;
.end method
