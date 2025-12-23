.class public final Llyiahf/vczjk/eq2;
.super Llyiahf/vczjk/ey0;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qt5;)V
    .locals 14

    sget-object v0, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    sget-object v2, Llyiahf/vczjk/uq2;->OooO0O0:Llyiahf/vczjk/iq2;

    sget-object v4, Llyiahf/vczjk/yk5;->OooOOOo:Llyiahf/vczjk/yk5;

    sget-object v5, Llyiahf/vczjk/ly0;->OooOOO0:Llyiahf/vczjk/ly0;

    sget-object v6, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v13, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    sget-object v7, Llyiahf/vczjk/q45;->OooO0o0:Llyiahf/vczjk/i45;

    move-object v1, p0

    move-object v3, p1

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/ey0;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/qt5;Llyiahf/vczjk/yk5;Llyiahf/vczjk/ly0;Ljava/util/List;Llyiahf/vczjk/q45;)V

    sget-object v10, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    new-instance v7, Llyiahf/vczjk/ux0;

    const/4 v9, 0x0

    const/4 v11, 0x1

    const/4 v12, 0x1

    move-object v8, p0

    invoke-direct/range {v7 .. v13}, Llyiahf/vczjk/ux0;-><init>(Llyiahf/vczjk/by0;Llyiahf/vczjk/il1;Llyiahf/vczjk/ko;ZILlyiahf/vczjk/sx8;)V

    move-object p1, v7

    move-object v1, v8

    sget-object v0, Llyiahf/vczjk/r72;->OooO0Oo:Llyiahf/vczjk/q72;

    invoke-virtual {p1, v6, v0}, Llyiahf/vczjk/ux0;->o0000o(Ljava/util/List;Llyiahf/vczjk/q72;)V

    sget-object v0, Llyiahf/vczjk/pq2;->OooOOo0:Llyiahf/vczjk/pq2;

    invoke-virtual {p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    iget-object v2, v2, Llyiahf/vczjk/qt5;->OooOOO0:Ljava/lang/String;

    const-string v3, ""

    filled-new-array {v2, v3}, [Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Llyiahf/vczjk/uq2;->OooO0O0(Llyiahf/vczjk/pq2;[Ljava/lang/String;)Llyiahf/vczjk/oq2;

    move-result-object v8

    move-object v10, v6

    new-instance v6, Llyiahf/vczjk/rq2;

    sget-object v9, Llyiahf/vczjk/tq2;->Oooo000:Llyiahf/vczjk/tq2;

    const/4 v0, 0x0

    new-array v2, v0, [Ljava/lang/String;

    invoke-static {v9, v2}, Llyiahf/vczjk/uq2;->OooO0Oo(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/sq2;

    move-result-object v7

    new-array v12, v0, [Ljava/lang/String;

    const/4 v11, 0x0

    invoke-direct/range {v6 .. v12}, Llyiahf/vczjk/rq2;-><init>(Llyiahf/vczjk/n3a;Llyiahf/vczjk/oq2;Llyiahf/vczjk/tq2;Ljava/util/List;Z[Ljava/lang/String;)V

    iput-object v6, p1, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    invoke-static {p1}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    invoke-virtual {p0, v8, v0, p1}, Llyiahf/vczjk/ey0;->o00ooo(Llyiahf/vczjk/jg5;Ljava/util/Set;Llyiahf/vczjk/ux0;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/x02;
    .locals 1

    const-string v0, "substitutor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public final OooOOOO(Llyiahf/vczjk/g5a;Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;
    .locals 1

    sget-object p2, Llyiahf/vczjk/pq2;->OooOOo0:Llyiahf/vczjk/pq2;

    invoke-virtual {p0}, Llyiahf/vczjk/oo0o0Oo;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qt5;->OooOOO0:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    filled-new-array {v0, p1}, [Ljava/lang/String;

    move-result-object p1

    invoke-static {p2, p1}, Llyiahf/vczjk/uq2;->OooO0O0(Llyiahf/vczjk/pq2;[Ljava/lang/String;)Llyiahf/vczjk/oq2;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/by0;
    .locals 1

    const-string v0, "substitutor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/oo0o0Oo;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "asString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method
