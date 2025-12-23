.class public final Llyiahf/vczjk/cv7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public final transient OooOOO0:Llyiahf/vczjk/kl4;


# direct methods
.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/kl4;

    const/16 v1, 0x14

    const/16 v2, 0xc8

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/kl4;-><init>(II)V

    iput-object v0, p0, Llyiahf/vczjk/cv7;->OooOOO0:Llyiahf/vczjk/kl4;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Class;Llyiahf/vczjk/fc5;)Llyiahf/vczjk/xa7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ky0;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ky0;-><init>(Ljava/lang/Class;)V

    iget-object v1, p0, Llyiahf/vczjk/cv7;->OooOOO0:Llyiahf/vczjk/kl4;

    iget-object v2, v1, Llyiahf/vczjk/kl4;->OooOOO:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v2, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xa7;

    if-eqz v2, :cond_0

    return-object v2

    :cond_0
    invoke-virtual {p2, p1}, Llyiahf/vczjk/ec5;->OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/h90;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object p2

    iget-object v2, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/yn;->Oooo0o(Llyiahf/vczjk/hm;)Llyiahf/vczjk/xa7;

    move-result-object p2

    if-eqz p2, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/xa7;->OooO0Oo()Z

    move-result v2

    if-nez v2, :cond_2

    :cond_1
    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object p2

    :cond_2
    invoke-virtual {v1, v0, p2}, Llyiahf/vczjk/kl4;->OooO00o(Ljava/io/Serializable;Ljava/lang/Object;)V

    return-object p2
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 1

    new-instance v0, Llyiahf/vczjk/cv7;

    invoke-direct {v0}, Llyiahf/vczjk/cv7;-><init>()V

    return-object v0
.end method
