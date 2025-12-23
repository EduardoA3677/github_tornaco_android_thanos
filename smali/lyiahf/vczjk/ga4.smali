.class public interface abstract annotation Llyiahf/vczjk/ga4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/annotation/Annotation;


# annotations
.annotation system Ldalvik/annotation/AnnotationDefault;
    value = .subannotation Llyiahf/vczjk/ga4;
        content = .enum Llyiahf/vczjk/ea4;->OooOOO0:Llyiahf/vczjk/ea4;
        contentFilter = Ljava/lang/Void;
        value = .enum Llyiahf/vczjk/ea4;->OooOOO0:Llyiahf/vczjk/ea4;
        valueFilter = Ljava/lang/Void;
    .end subannotation
.end annotation

.annotation runtime Ljava/lang/annotation/Retention;
    value = .enum Ljava/lang/annotation/RetentionPolicy;->RUNTIME:Ljava/lang/annotation/RetentionPolicy;
.end annotation


# virtual methods
.method public abstract content()Llyiahf/vczjk/ea4;
.end method

.method public abstract contentFilter()Ljava/lang/Class;
.end method

.method public abstract value()Llyiahf/vczjk/ea4;
.end method

.method public abstract valueFilter()Ljava/lang/Class;
.end method
