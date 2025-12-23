.class public interface abstract annotation Llyiahf/vczjk/r94;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/annotation/Annotation;


# annotations
.annotation system Ldalvik/annotation/AnnotationDefault;
    value = .subannotation Llyiahf/vczjk/r94;
        lenient = .enum Llyiahf/vczjk/df6;->OooOOO:Llyiahf/vczjk/df6;
        locale = "##default"
        pattern = ""
        shape = .enum Llyiahf/vczjk/p94;->OooOOO0:Llyiahf/vczjk/p94;
        timezone = "##default"
        with = {}
        without = {}
    .end subannotation
.end annotation

.annotation runtime Ljava/lang/annotation/Retention;
    value = .enum Ljava/lang/annotation/RetentionPolicy;->RUNTIME:Ljava/lang/annotation/RetentionPolicy;
.end annotation


# virtual methods
.method public abstract lenient()Llyiahf/vczjk/df6;
.end method

.method public abstract locale()Ljava/lang/String;
.end method

.method public abstract pattern()Ljava/lang/String;
.end method

.method public abstract shape()Llyiahf/vczjk/p94;
.end method

.method public abstract timezone()Ljava/lang/String;
.end method

.method public abstract with()[Llyiahf/vczjk/n94;
.end method

.method public abstract without()[Llyiahf/vczjk/n94;
.end method
