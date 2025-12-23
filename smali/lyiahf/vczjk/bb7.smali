.class public final Llyiahf/vczjk/bb7;
.super Llyiahf/vczjk/gb7;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/lang/Class;

.field public final OooO0O0:Ljava/lang/Class;

.field public final OooO0OO:Llyiahf/vczjk/zb4;

.field public final OooO0Oo:Llyiahf/vczjk/zb4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb7;Ljava/lang/Class;Llyiahf/vczjk/zb4;Ljava/lang/Class;Llyiahf/vczjk/zb4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/bb7;->OooO00o:Ljava/lang/Class;

    iput-object p3, p0, Llyiahf/vczjk/bb7;->OooO0OO:Llyiahf/vczjk/zb4;

    iput-object p4, p0, Llyiahf/vczjk/bb7;->OooO0O0:Ljava/lang/Class;

    iput-object p5, p0, Llyiahf/vczjk/bb7;->OooO0Oo:Llyiahf/vczjk/zb4;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;
    .locals 4

    new-instance v0, Llyiahf/vczjk/fb7;

    iget-object v1, p0, Llyiahf/vczjk/bb7;->OooO00o:Ljava/lang/Class;

    iget-object v2, p0, Llyiahf/vczjk/bb7;->OooO0OO:Llyiahf/vczjk/zb4;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/fb7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/zb4;)V

    new-instance v1, Llyiahf/vczjk/fb7;

    iget-object v2, p0, Llyiahf/vczjk/bb7;->OooO0O0:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/bb7;->OooO0Oo:Llyiahf/vczjk/zb4;

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/fb7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/zb4;)V

    new-instance v2, Llyiahf/vczjk/fb7;

    invoke-direct {v2, p1, p2}, Llyiahf/vczjk/fb7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/zb4;)V

    filled-new-array {v0, v1, v2}, [Llyiahf/vczjk/fb7;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/db7;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/db7;-><init>(Llyiahf/vczjk/gb7;[Llyiahf/vczjk/fb7;)V

    return-object p2
.end method

.method public final OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bb7;->OooO00o:Ljava/lang/Class;

    if-ne p1, v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/bb7;->OooO0OO:Llyiahf/vczjk/zb4;

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/bb7;->OooO0O0:Ljava/lang/Class;

    if-ne p1, v0, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/bb7;->OooO0Oo:Llyiahf/vczjk/zb4;

    return-object p1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method
