.class public final Llyiahf/vczjk/to;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/cb0;

.field public final OooO0O0:Llyiahf/vczjk/pm;

.field public OooO0OO:Llyiahf/vczjk/zb4;

.field public OooO0Oo:Llyiahf/vczjk/vb5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cb0;Llyiahf/vczjk/pm;Llyiahf/vczjk/zb4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/to;->OooO0O0:Llyiahf/vczjk/pm;

    iput-object p1, p0, Llyiahf/vczjk/to;->OooO00o:Llyiahf/vczjk/cb0;

    iput-object p3, p0, Llyiahf/vczjk/to;->OooO0OO:Llyiahf/vczjk/zb4;

    instance-of p1, p3, Llyiahf/vczjk/vb5;

    if-eqz p1, :cond_0

    check-cast p3, Llyiahf/vczjk/vb5;

    iput-object p3, p0, Llyiahf/vczjk/to;->OooO0Oo:Llyiahf/vczjk/vb5;

    :cond_0
    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/to;->OooO0O0:Llyiahf/vczjk/pm;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pm;->o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    return-void

    :cond_0
    instance-of v1, p1, Ljava/util/Map;

    if-eqz v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/to;->OooO0Oo:Llyiahf/vczjk/vb5;

    if-eqz v0, :cond_1

    check-cast p1, Ljava/util/Map;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/vb5;->OooOOo(Ljava/util/Map;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/to;->OooO0OO:Llyiahf/vczjk/zb4;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_2
    iget-object p2, p0, Llyiahf/vczjk/to;->OooO00o:Llyiahf/vczjk/cb0;

    invoke-virtual {p2}, Llyiahf/vczjk/cb0;->getType()Llyiahf/vczjk/x64;

    move-result-object p2

    invoke-virtual {v0}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    const-string v1, "Value returned by \'any-getter\' "

    const-string v2, "() not java.util.Map but "

    invoke-static {v1, v0, v2, p1}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/tg8;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method
