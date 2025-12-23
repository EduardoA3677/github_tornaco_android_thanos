.class public interface abstract annotation Llyiahf/vczjk/nc4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/annotation/Annotation;


# annotations
.annotation system Ldalvik/annotation/AnnotationDefault;
    value = .subannotation Llyiahf/vczjk/nc4;
        defaultImpl = Llyiahf/vczjk/nc4;
        include = .enum Llyiahf/vczjk/kc4;->OooOOO0:Llyiahf/vczjk/kc4;
        property = ""
        visible = false
    .end subannotation
.end annotation

.annotation runtime Ljava/lang/annotation/Retention;
    value = .enum Ljava/lang/annotation/RetentionPolicy;->RUNTIME:Ljava/lang/annotation/RetentionPolicy;
.end annotation


# virtual methods
.method public abstract defaultImpl()Ljava/lang/Class;
.end method

.method public abstract include()Llyiahf/vczjk/kc4;
.end method

.method public abstract property()Ljava/lang/String;
.end method

.method public abstract use()Llyiahf/vczjk/lc4;
.end method

.method public abstract visible()Z
.end method
