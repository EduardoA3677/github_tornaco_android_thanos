.class public final Llyiahf/vczjk/m06;
.super Llyiahf/vczjk/dp8;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qq0;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/kq0;

.field public final OooOOOO:Llyiahf/vczjk/n06;

.field public final OooOOOo:Llyiahf/vczjk/iaa;

.field public final OooOOo:Z

.field public final OooOOo0:Llyiahf/vczjk/d3a;

.field public final OooOOoo:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kq0;Llyiahf/vczjk/n06;Llyiahf/vczjk/iaa;Llyiahf/vczjk/d3a;ZI)V
    .locals 7

    and-int/lit8 v0, p6, 0x8

    if-eqz v0, :cond_0

    sget-object p4, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p4, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    :cond_0
    move-object v4, p4

    and-int/lit8 p4, p6, 0x10

    if-eqz p4, :cond_1

    const/4 p5, 0x0

    :cond_1
    move v5, p5

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/m06;-><init>(Llyiahf/vczjk/kq0;Llyiahf/vczjk/n06;Llyiahf/vczjk/iaa;Llyiahf/vczjk/d3a;ZZ)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/kq0;Llyiahf/vczjk/n06;Llyiahf/vczjk/iaa;Llyiahf/vczjk/d3a;ZZ)V
    .locals 1

    const-string v0, "captureStatus"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "constructor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "attributes"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/m06;->OooOOO:Llyiahf/vczjk/kq0;

    iput-object p2, p0, Llyiahf/vczjk/m06;->OooOOOO:Llyiahf/vczjk/n06;

    iput-object p3, p0, Llyiahf/vczjk/m06;->OooOOOo:Llyiahf/vczjk/iaa;

    iput-object p4, p0, Llyiahf/vczjk/m06;->OooOOo0:Llyiahf/vczjk/d3a;

    iput-boolean p5, p0, Llyiahf/vczjk/m06;->OooOOo:Z

    iput-boolean p6, p0, Llyiahf/vczjk/m06;->OooOOoo:Z

    return-void
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/jg5;
    .locals 3

    sget-object v0, Llyiahf/vczjk/pq2;->OooOOO0:Llyiahf/vczjk/pq2;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/String;

    const/4 v2, 0x1

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/uq2;->OooO00o(Llyiahf/vczjk/pq2;Z[Ljava/lang/String;)Llyiahf/vczjk/oq2;

    move-result-object v0

    return-object v0
.end method

.method public final o000000()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m06;->OooOOOO:Llyiahf/vczjk/n06;

    return-object v0
.end method

.method public final o000000o()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/m06;->OooOOo:Z

    return v0
.end method

.method public final bridge synthetic o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/m06;->o00000oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/m06;

    move-result-object p1

    return-object p1
.end method

.method public final o00000OO(Z)Llyiahf/vczjk/iaa;
    .locals 7

    new-instance v0, Llyiahf/vczjk/m06;

    iget-object v2, p0, Llyiahf/vczjk/m06;->OooOOOO:Llyiahf/vczjk/n06;

    const/16 v6, 0x20

    iget-object v1, p0, Llyiahf/vczjk/m06;->OooOOO:Llyiahf/vczjk/kq0;

    iget-object v3, p0, Llyiahf/vczjk/m06;->OooOOOo:Llyiahf/vczjk/iaa;

    iget-object v4, p0, Llyiahf/vczjk/m06;->OooOOo0:Llyiahf/vczjk/d3a;

    move v5, p1

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/m06;-><init>(Llyiahf/vczjk/kq0;Llyiahf/vczjk/n06;Llyiahf/vczjk/iaa;Llyiahf/vczjk/d3a;ZI)V

    return-object v0
.end method

.method public final bridge synthetic o00000Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/iaa;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/m06;->o00000oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/m06;

    move-result-object p1

    return-object p1
.end method

.method public final o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 8

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/m06;

    iget-object v4, p0, Llyiahf/vczjk/m06;->OooOOOo:Llyiahf/vczjk/iaa;

    iget-boolean v6, p0, Llyiahf/vczjk/m06;->OooOOo:Z

    iget-object v2, p0, Llyiahf/vczjk/m06;->OooOOO:Llyiahf/vczjk/kq0;

    iget-object v3, p0, Llyiahf/vczjk/m06;->OooOOOO:Llyiahf/vczjk/n06;

    iget-boolean v7, p0, Llyiahf/vczjk/m06;->OooOOoo:Z

    move-object v5, p1

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/m06;-><init>(Llyiahf/vczjk/kq0;Llyiahf/vczjk/n06;Llyiahf/vczjk/iaa;Llyiahf/vczjk/d3a;ZZ)V

    return-object v1
.end method

.method public final o00000oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/m06;
    .locals 11

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/m06;->OooOOOO:Llyiahf/vczjk/n06;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/n06;->OooO00o:Llyiahf/vczjk/z4a;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/z4a;->OooO0Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/z4a;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/n06;->OooO0O0:Llyiahf/vczjk/le3;

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    new-instance v2, Llyiahf/vczjk/o0O000;

    const/16 v4, 0x1b

    const/4 v5, 0x0

    invoke-direct {v2, v4, v0, p1, v5}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    goto :goto_0

    :cond_0
    move-object v2, v3

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/n06;->OooO0OO:Llyiahf/vczjk/n06;

    if-nez p1, :cond_1

    move-object p1, v0

    :cond_1
    new-instance v6, Llyiahf/vczjk/n06;

    iget-object v0, v0, Llyiahf/vczjk/n06;->OooO0Oo:Llyiahf/vczjk/t4a;

    invoke-direct {v6, v1, v2, p1, v0}, Llyiahf/vczjk/n06;-><init>(Llyiahf/vczjk/z4a;Llyiahf/vczjk/le3;Llyiahf/vczjk/n06;Llyiahf/vczjk/t4a;)V

    iget-object p1, p0, Llyiahf/vczjk/m06;->OooOOOo:Llyiahf/vczjk/iaa;

    if-eqz p1, :cond_2

    move-object v7, p1

    goto :goto_1

    :cond_2
    move-object v7, v3

    :goto_1
    new-instance v4, Llyiahf/vczjk/m06;

    iget-boolean v9, p0, Llyiahf/vczjk/m06;->OooOOo:Z

    const/16 v10, 0x20

    iget-object v5, p0, Llyiahf/vczjk/m06;->OooOOO:Llyiahf/vczjk/kq0;

    iget-object v8, p0, Llyiahf/vczjk/m06;->OooOOo0:Llyiahf/vczjk/d3a;

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/m06;-><init>(Llyiahf/vczjk/kq0;Llyiahf/vczjk/n06;Llyiahf/vczjk/iaa;Llyiahf/vczjk/d3a;ZI)V

    return-object v4
.end method

.method public final o0000Ooo(Z)Llyiahf/vczjk/dp8;
    .locals 7

    new-instance v0, Llyiahf/vczjk/m06;

    iget-object v2, p0, Llyiahf/vczjk/m06;->OooOOOO:Llyiahf/vczjk/n06;

    const/16 v6, 0x20

    iget-object v1, p0, Llyiahf/vczjk/m06;->OooOOO:Llyiahf/vczjk/kq0;

    iget-object v3, p0, Llyiahf/vczjk/m06;->OooOOOo:Llyiahf/vczjk/iaa;

    iget-object v4, p0, Llyiahf/vczjk/m06;->OooOOo0:Llyiahf/vczjk/d3a;

    move v5, p1

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/m06;-><init>(Llyiahf/vczjk/kq0;Llyiahf/vczjk/n06;Llyiahf/vczjk/iaa;Llyiahf/vczjk/d3a;ZI)V

    return-object v0
.end method

.method public final o00ooo()Ljava/util/List;
    .locals 1

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final o0OOO0o()Llyiahf/vczjk/d3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m06;->OooOOo0:Llyiahf/vczjk/d3a;

    return-object v0
.end method
