.class public final Llyiahf/vczjk/pd4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lh6;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/q45;

.field public final OooO0O0:Llyiahf/vczjk/dm5;

.field public OooO0OO:Llyiahf/vczjk/s72;

.field public final OooO0Oo:Llyiahf/vczjk/r60;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/tg7;Llyiahf/vczjk/dm5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pd4;->OooO00o:Llyiahf/vczjk/q45;

    iput-object p3, p0, Llyiahf/vczjk/pd4;->OooO0O0:Llyiahf/vczjk/dm5;

    new-instance p2, Llyiahf/vczjk/oo000o;

    const/4 p3, 0x2

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0OO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/r60;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/pd4;->OooO0Oo:Llyiahf/vczjk/r60;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hc3;)Z
    .locals 3

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/pd4;->OooO0Oo:Llyiahf/vczjk/r60;

    iget-object v1, v0, Llyiahf/vczjk/r60;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_0

    sget-object v2, Llyiahf/vczjk/p45;->OooOOO:Llyiahf/vczjk/p45;

    if-eq v1, v2, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/hh6;

    goto :goto_0

    :cond_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/pd4;->OooO0OO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hk0;

    move-result-object p1

    :goto_0
    if-nez p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/hc3;Ljava/util/ArrayList;)V
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/pd4;->OooO0Oo:Llyiahf/vczjk/r60;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p2, p1}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hk0;
    .locals 3

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/x09;->OooOO0O:Llyiahf/vczjk/qt5;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/hc3;->OooO0OO(Llyiahf/vczjk/qt5;)Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    move-object v0, v1

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/bk0;->OooOOO0:Llyiahf/vczjk/bk0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/bk0;->OooO00o(Llyiahf/vczjk/hc3;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/jk0;->OooO00o(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object v0

    :goto_0
    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/pd4;->OooO00o:Llyiahf/vczjk/q45;

    iget-object v2, p0, Llyiahf/vczjk/pd4;->OooO0O0:Llyiahf/vczjk/dm5;

    invoke-static {p1, v1, v2, v0}, Llyiahf/vczjk/c6a;->Oooo00O(Llyiahf/vczjk/hc3;Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;Ljava/io/InputStream;)Llyiahf/vczjk/hk0;

    move-result-object p1

    return-object p1

    :cond_1
    return-object v1
.end method

.method public final OooO0oo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 0

    const-string p2, "fqName"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1
.end method
