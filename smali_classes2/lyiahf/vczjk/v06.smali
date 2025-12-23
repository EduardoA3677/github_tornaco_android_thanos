.class public final Llyiahf/vczjk/v06;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u06;


# instance fields
.field public final OooO0OO:Llyiahf/vczjk/zk4;

.field public final OooO0Oo:Llyiahf/vczjk/ng6;


# direct methods
.method public constructor <init>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/zk4;->OooO00o:Llyiahf/vczjk/zk4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/v06;->OooO0OO:Llyiahf/vczjk/zk4;

    new-instance v0, Llyiahf/vczjk/ng6;

    sget-object v1, Llyiahf/vczjk/ng6;->OooO0Oo:Llyiahf/vczjk/e86;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ng6;-><init>(Llyiahf/vczjk/vk4;)V

    iput-object v0, p0, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z
    .locals 4

    const-string v0, "a"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/v06;->OooO0OO:Llyiahf/vczjk/zk4;

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x6

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/c6a;->Oooo00o(ZLlyiahf/vczjk/uk2;Llyiahf/vczjk/zk4;I)Llyiahf/vczjk/l3a;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p2

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/xj0;->OooOOO(Llyiahf/vczjk/l3a;Llyiahf/vczjk/yk4;Llyiahf/vczjk/yk4;)Z

    move-result p1

    return p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z
    .locals 4

    const-string v0, "subtype"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "supertype"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/v06;->OooO0OO:Llyiahf/vczjk/zk4;

    const/4 v1, 0x1

    const/4 v2, 0x0

    const/4 v3, 0x6

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/c6a;->Oooo00o(ZLlyiahf/vczjk/uk2;Llyiahf/vczjk/zk4;I)Llyiahf/vczjk/l3a;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p2

    sget-object v1, Llyiahf/vczjk/xj0;->OooOOOO:Llyiahf/vczjk/xj0;

    invoke-static {v1, v0, p1, p2}, Llyiahf/vczjk/xj0;->OooOo0O(Llyiahf/vczjk/xj0;Llyiahf/vczjk/l3a;Llyiahf/vczjk/yk4;Llyiahf/vczjk/yk4;)Z

    move-result p1

    return p1
.end method
