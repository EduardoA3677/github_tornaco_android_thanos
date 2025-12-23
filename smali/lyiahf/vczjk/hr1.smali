.class public final Llyiahf/vczjk/hr1;
.super Llyiahf/vczjk/m52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ne8;


# instance fields
.field public OooOoo:Llyiahf/vczjk/gy9;

.field public OooOooO:Llyiahf/vczjk/gl9;

.field public OooOooo:Llyiahf/vczjk/lx4;

.field public Oooo0:Llyiahf/vczjk/mk9;

.field public Oooo000:Z

.field public Oooo00O:Z

.field public Oooo00o:Llyiahf/vczjk/s86;

.field public Oooo0O0:Llyiahf/vczjk/wv3;

.field public Oooo0OO:Llyiahf/vczjk/w83;


# direct methods
.method public static final o0000Ooo(Llyiahf/vczjk/hr1;Llyiahf/vczjk/lx4;Ljava/lang/String;ZZ)V
    .locals 5

    const/4 v0, 0x1

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-nez p3, :cond_2

    if-nez p4, :cond_0

    goto :goto_0

    :cond_0
    iget-object p0, p1, Llyiahf/vczjk/lx4;->OooO0o0:Llyiahf/vczjk/yl9;

    iget-object p3, p1, Llyiahf/vczjk/lx4;->OooOo0O:Llyiahf/vczjk/kx4;

    const/4 p4, 0x0

    if-eqz p0, :cond_1

    new-instance v1, Llyiahf/vczjk/x52;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/n41;

    invoke-direct {v2, p2, v0}, Llyiahf/vczjk/n41;-><init>(Ljava/lang/String;I)V

    const/4 v3, 0x2

    new-array v3, v3, [Llyiahf/vczjk/vk2;

    const/4 v4, 0x0

    aput-object v1, v3, v4

    aput-object v2, v3, v0

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooO0Oo:Llyiahf/vczjk/xk2;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/xk2;->OooO00o(Ljava/util/List;)Llyiahf/vczjk/gl9;

    move-result-object p1

    invoke-virtual {p0, p4, p1}, Llyiahf/vczjk/yl9;->OooO00o(Llyiahf/vczjk/gl9;Llyiahf/vczjk/gl9;)V

    invoke-virtual {p3, p1}, Llyiahf/vczjk/kx4;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :cond_1
    if-nez p4, :cond_2

    new-instance p0, Llyiahf/vczjk/gl9;

    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result p1

    invoke-static {p1, p1}, Llyiahf/vczjk/rd3;->OooO0O0(II)J

    move-result-wide v0

    const/4 p1, 0x4

    invoke-direct {p0, p2, v0, v1, p1}, Llyiahf/vczjk/gl9;-><init>(Ljava/lang/String;JI)V

    invoke-virtual {p3, p0}, Llyiahf/vczjk/kx4;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    :goto_0
    return-void
.end method


# virtual methods
.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/hr1;->OooOooO:Llyiahf/vczjk/gl9;

    iget-object v0, v0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v1, Llyiahf/vczjk/ve8;->OooOoo:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v3, 0x10

    aget-object v3, v2, v3

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/hr1;->OooOoo:Llyiahf/vczjk/gy9;

    iget-object v0, v0, Llyiahf/vczjk/gy9;->OooO00o:Llyiahf/vczjk/an;

    sget-object v1, Llyiahf/vczjk/ve8;->OooOooO:Llyiahf/vczjk/ze8;

    const/16 v3, 0x11

    aget-object v3, v2, v3

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/hr1;->OooOooO:Llyiahf/vczjk/gl9;

    iget-wide v0, v0, Llyiahf/vczjk/gl9;->OooO0O0:J

    sget-object v3, Llyiahf/vczjk/ve8;->OooOooo:Llyiahf/vczjk/ze8;

    const/16 v4, 0x12

    aget-object v4, v2, v4

    new-instance v4, Llyiahf/vczjk/gn9;

    invoke-direct {v4, v0, v1}, Llyiahf/vczjk/gn9;-><init>(J)V

    invoke-virtual {v3, p1, v4}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/tp3;->OooOOOO:Llyiahf/vczjk/hc;

    sget-object v1, Llyiahf/vczjk/ve8;->OooOOo0:Llyiahf/vczjk/ze8;

    const/16 v3, 0x8

    aget-object v3, v2, v3

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/xq1;

    invoke-direct {v0, p0}, Llyiahf/vczjk/xq1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooO0oO:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    const/4 v4, 0x0

    invoke-direct {v3, v4, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/je8;

    invoke-virtual {v0, v1, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-boolean v1, p0, Llyiahf/vczjk/hr1;->Oooo00O:Z

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/ve8;->OooO:Llyiahf/vczjk/ze8;

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, v1, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_0
    iget-boolean v1, p0, Llyiahf/vczjk/hr1;->Oooo00O:Z

    if-eqz v1, :cond_1

    iget-boolean v1, p0, Llyiahf/vczjk/hr1;->Oooo000:Z

    if-nez v1, :cond_1

    const/4 v1, 0x1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_0
    sget-object v3, Llyiahf/vczjk/ve8;->Oooo0o0:Llyiahf/vczjk/ze8;

    const/16 v5, 0x18

    aget-object v2, v2, v5

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    invoke-virtual {v3, p1, v2}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/yq1;

    invoke-direct {v2, p0}, Llyiahf/vczjk/yq1;-><init>(Llyiahf/vczjk/hr1;)V

    invoke-static {p1, v2}, Llyiahf/vczjk/ye8;->OooO0OO(Llyiahf/vczjk/af8;Llyiahf/vczjk/oe3;)V

    if-eqz v1, :cond_2

    new-instance v1, Llyiahf/vczjk/zq1;

    invoke-direct {v1, p0}, Llyiahf/vczjk/zq1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOO0:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    invoke-direct {v3, v4, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/ar1;

    invoke-direct {v1, p0, p1}, Llyiahf/vczjk/ar1;-><init>(Llyiahf/vczjk/hr1;Llyiahf/vczjk/af8;)V

    sget-object p1, Llyiahf/vczjk/ie8;->OooOOO:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    invoke-direct {v2, v4, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_2
    new-instance p1, Llyiahf/vczjk/br1;

    invoke-direct {p1, p0}, Llyiahf/vczjk/br1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooO:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    invoke-direct {v2, v4, p1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/hr1;->Oooo0O0:Llyiahf/vczjk/wv3;

    iget p1, p1, Llyiahf/vczjk/wv3;->OooO0o0:I

    new-instance v1, Llyiahf/vczjk/cr1;

    invoke-direct {v1, p0}, Llyiahf/vczjk/cr1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v2, Llyiahf/vczjk/ve8;->Oooo000:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/vv3;

    invoke-direct {v3, p1}, Llyiahf/vczjk/vv3;-><init>(I)V

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/ie8;->OooOOOO:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    invoke-direct {v2, v4, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/dr1;

    invoke-direct {p1, p0}, Llyiahf/vczjk/dr1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooO0O0:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    invoke-direct {v2, v4, p1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/er1;

    invoke-direct {p1, p0}, Llyiahf/vczjk/er1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooO0OO:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    invoke-direct {v2, v4, p1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/hr1;->OooOooO:Llyiahf/vczjk/gl9;

    iget-wide v1, p1, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result p1

    if-nez p1, :cond_3

    new-instance p1, Llyiahf/vczjk/fr1;

    invoke-direct {p1, p0}, Llyiahf/vczjk/fr1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooOOOo:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    invoke-direct {v2, v4, p1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-boolean p1, p0, Llyiahf/vczjk/hr1;->Oooo00O:Z

    if-eqz p1, :cond_3

    iget-boolean p1, p0, Llyiahf/vczjk/hr1;->Oooo000:Z

    if-nez p1, :cond_3

    new-instance p1, Llyiahf/vczjk/vq1;

    invoke-direct {p1, p0}, Llyiahf/vczjk/vq1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooOOo0:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    invoke-direct {v2, v4, p1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_3
    iget-boolean p1, p0, Llyiahf/vczjk/hr1;->Oooo00O:Z

    if-eqz p1, :cond_4

    iget-boolean p1, p0, Llyiahf/vczjk/hr1;->Oooo000:Z

    if-nez p1, :cond_4

    new-instance p1, Llyiahf/vczjk/wq1;

    invoke-direct {p1, p0}, Llyiahf/vczjk/wq1;-><init>(Llyiahf/vczjk/hr1;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooOOo:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    invoke-direct {v2, v4, p1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_4
    return-void
.end method

.method public final o0ooOoO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method
