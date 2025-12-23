.class public Llyiahf/vczjk/oq2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/jg5;


# instance fields
.field public final OooO0O0:Ljava/lang/String;


# direct methods
.method public varargs constructor <init>(Llyiahf/vczjk/pq2;[Ljava/lang/String;)V
    .locals 1

    const-string v0, "formatParams"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p1}, Llyiahf/vczjk/pq2;->OooO00o()Ljava/lang/String;

    move-result-object p1

    array-length v0, p2

    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    array-length v0, p2

    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    invoke-static {p1, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/oq2;->OooO0O0:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Set;
    .locals 0

    const-string p2, "name"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/uq2;->OooO0o:Ljava/util/Set;

    return-object p1
.end method

.method public OooO00o()Ljava/util/Set;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object v0
.end method

.method public OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;
    .locals 2

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p2, Llyiahf/vczjk/eq2;

    sget-object v0, Llyiahf/vczjk/gq2;->OooOOO0:Llyiahf/vczjk/gq2;

    invoke-virtual {v0}, Llyiahf/vczjk/gq2;->OooO00o()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/eq2;-><init>(Llyiahf/vczjk/qt5;)V

    return-object p2
.end method

.method public OooO0OO()Ljava/util/Set;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object v0
.end method

.method public bridge synthetic OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 0

    check-cast p2, Llyiahf/vczjk/h16;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/oq2;->OooO0oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Set;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 0

    const-string p2, "kindFilter"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1
.end method

.method public bridge synthetic OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/oq2;->OooO(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Set;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public OooO0oO()Ljava/util/Set;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object v0
.end method

.method public OooO0oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Set;
    .locals 9

    const-string p2, "name"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/hq2;

    sget-object v1, Llyiahf/vczjk/uq2;->OooO0OO:Llyiahf/vczjk/eq2;

    const-string p1, "containingDeclaration"

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    sget-object p1, Llyiahf/vczjk/gq2;->OooOOO:Llyiahf/vczjk/gq2;

    invoke-virtual {p1}, Llyiahf/vczjk/gq2;->OooO00o()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    const/4 v2, 0x0

    const/4 v5, 0x1

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ho8;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ho8;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/sx8;)V

    sget-object v3, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object p1, Llyiahf/vczjk/tq2;->OooOOOO:Llyiahf/vczjk/tq2;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/String;

    invoke-static {p1, p2}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/yk5;->OooOOOo:Llyiahf/vczjk/yk5;

    sget-object v8, Llyiahf/vczjk/r72;->OooO0o0:Llyiahf/vczjk/q72;

    const/4 v1, 0x0

    move-object v4, v3

    move-object v5, v3

    invoke-virtual/range {v0 .. v8}, Llyiahf/vczjk/ho8;->o0000o0o(Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/uk4;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;)Llyiahf/vczjk/ho8;

    invoke-static {v0}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object p1

    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "ErrorScope{"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/oq2;->OooO0O0:Ljava/lang/String;

    const/16 v2, 0x7d

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/ii5;->OooOO0O(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
