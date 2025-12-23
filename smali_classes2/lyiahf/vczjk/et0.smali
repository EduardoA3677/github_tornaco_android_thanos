.class public final Llyiahf/vczjk/et0;
.super Llyiahf/vczjk/ys0;
.source "SourceFile"


# instance fields
.field public final OooOOo0:Llyiahf/vczjk/eb9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/f43;Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V
    .locals 0

    invoke-direct {p0, p4, p5, p3, p2}, Llyiahf/vczjk/ys0;-><init>(ILlyiahf/vczjk/aj0;Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;)V

    check-cast p1, Llyiahf/vczjk/eb9;

    iput-object p1, p0, Llyiahf/vczjk/et0;->OooOOo0:Llyiahf/vczjk/eb9;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/vs0;
    .locals 6

    new-instance v0, Llyiahf/vczjk/et0;

    iget-object v1, p0, Llyiahf/vczjk/et0;->OooOOo0:Llyiahf/vczjk/eb9;

    iget-object v2, p0, Llyiahf/vczjk/ys0;->OooOOOo:Llyiahf/vczjk/f43;

    move-object v3, p1

    move v4, p2

    move-object v5, p3

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/et0;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/f43;Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V

    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/dt0;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/dt0;-><init>(Llyiahf/vczjk/et0;Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
