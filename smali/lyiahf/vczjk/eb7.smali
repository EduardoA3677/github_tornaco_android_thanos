.class public final Llyiahf/vczjk/eb7;
.super Llyiahf/vczjk/gb7;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/lang/Class;

.field public final OooO0O0:Llyiahf/vczjk/zb4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gb7;Ljava/lang/Class;Llyiahf/vczjk/zb4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/eb7;->OooO00o:Ljava/lang/Class;

    iput-object p3, p0, Llyiahf/vczjk/eb7;->OooO0O0:Llyiahf/vczjk/zb4;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;
    .locals 6

    new-instance v0, Llyiahf/vczjk/bb7;

    iget-object v2, p0, Llyiahf/vczjk/eb7;->OooO00o:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/eb7;->OooO0O0:Llyiahf/vczjk/zb4;

    move-object v1, p0

    move-object v4, p1

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bb7;-><init>(Llyiahf/vczjk/eb7;Ljava/lang/Class;Llyiahf/vczjk/zb4;Ljava/lang/Class;Llyiahf/vczjk/zb4;)V

    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eb7;->OooO00o:Ljava/lang/Class;

    if-ne p1, v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/eb7;->OooO0O0:Llyiahf/vczjk/zb4;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method
