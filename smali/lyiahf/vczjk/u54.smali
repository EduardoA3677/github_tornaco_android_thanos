.class public interface abstract annotation Llyiahf/vczjk/u54;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/annotation/Annotation;


# annotations
.annotation system Ldalvik/annotation/AnnotationDefault;
    value = .subannotation Llyiahf/vczjk/u54;
        useInput = .enum Llyiahf/vczjk/df6;->OooOOO:Llyiahf/vczjk/df6;
        value = ""
    .end subannotation
.end annotation

.annotation runtime Ljava/lang/annotation/Retention;
    value = .enum Ljava/lang/annotation/RetentionPolicy;->RUNTIME:Ljava/lang/annotation/RetentionPolicy;
.end annotation


# virtual methods
.method public abstract useInput()Llyiahf/vczjk/df6;
.end method

.method public abstract value()Ljava/lang/String;
.end method
