.class public final Llyiahf/vczjk/ft9;
.super Llyiahf/vczjk/wz0;
.source "SourceFile"


# instance fields
.field public OoooO:Z

.field public OoooOO0:Llyiahf/vczjk/oe3;

.field public final o000oOoO:Llyiahf/vczjk/et9;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)V
    .locals 7

    new-instance v6, Llyiahf/vczjk/dt9;

    invoke-direct {v6, p6, p1}, Llyiahf/vczjk/dt9;-><init>(Llyiahf/vczjk/oe3;Z)V

    const/4 v4, 0x0

    move-object v0, p0

    move-object v1, p2

    move-object v2, p3

    move v3, p4

    move-object v5, p5

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/o0000O0O;-><init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLjava/lang/String;Llyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)V

    iput-boolean p1, v0, Llyiahf/vczjk/ft9;->OoooO:Z

    iput-object p6, v0, Llyiahf/vczjk/ft9;->OoooOO0:Llyiahf/vczjk/oe3;

    new-instance p1, Llyiahf/vczjk/et9;

    invoke-direct {p1, p0}, Llyiahf/vczjk/et9;-><init>(Llyiahf/vczjk/ft9;)V

    iput-object p1, v0, Llyiahf/vczjk/ft9;->o000oOoO:Llyiahf/vczjk/et9;

    return-void
.end method


# virtual methods
.method public final o0000Ooo(Llyiahf/vczjk/af8;)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/ft9;->OoooO:Z

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/gt9;->OooOOO0:Llyiahf/vczjk/gt9;

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/gt9;->OooOOO:Llyiahf/vczjk/gt9;

    :goto_0
    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v1, Llyiahf/vczjk/ve8;->Oooo00o:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v3, 0x17

    aget-object v2, v2, v3

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    return-void
.end method
