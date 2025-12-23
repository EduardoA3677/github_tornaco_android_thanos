.class public final synthetic Llyiahf/vczjk/p32;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/nw7;

.field public final synthetic OooO0O0:Llyiahf/vczjk/gv2;

.field public final synthetic OooO0OO:Z


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p32;->OooO00o:Llyiahf/vczjk/nw7;

    iput-object p2, p0, Llyiahf/vczjk/p32;->OooO0O0:Llyiahf/vczjk/gv2;

    iput-boolean p3, p0, Llyiahf/vczjk/p32;->OooO0OO:Z

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 2

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/p32;->OooO0O0:Llyiahf/vczjk/gv2;

    iget-boolean v0, p0, Llyiahf/vczjk/p32;->OooO0OO:Z

    iget-object v1, p0, Llyiahf/vczjk/p32;->OooO00o:Llyiahf/vczjk/nw7;

    invoke-static {v1, p1, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->OooO0o(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Z)V

    return-void

    :cond_0
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method
