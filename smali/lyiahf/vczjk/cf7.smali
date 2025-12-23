.class public final Llyiahf/vczjk/cf7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $refreshing:Z

.field final synthetic $refreshingOffsetPx:Llyiahf/vczjk/el7;

.field final synthetic $state:Llyiahf/vczjk/bf7;

.field final synthetic $thresholdPx:Llyiahf/vczjk/el7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf7;ZLlyiahf/vczjk/el7;Llyiahf/vczjk/el7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cf7;->$state:Llyiahf/vczjk/bf7;

    iput-boolean p2, p0, Llyiahf/vczjk/cf7;->$refreshing:Z

    iput-object p3, p0, Llyiahf/vczjk/cf7;->$thresholdPx:Llyiahf/vczjk/el7;

    iput-object p4, p0, Llyiahf/vczjk/cf7;->$refreshingOffsetPx:Llyiahf/vczjk/el7;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/cf7;->$state:Llyiahf/vczjk/bf7;

    iget-boolean v1, p0, Llyiahf/vczjk/cf7;->$refreshing:Z

    invoke-virtual {v0}, Llyiahf/vczjk/bf7;->OooO0OO()Z

    move-result v2

    const/4 v3, 0x3

    const/4 v4, 0x0

    if-eq v2, v1, :cond_1

    iget-object v2, v0, Llyiahf/vczjk/bf7;->OooO0Oo:Llyiahf/vczjk/qs5;

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v5

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/bf7;->OooO0o:Llyiahf/vczjk/lr5;

    check-cast v2, Llyiahf/vczjk/zv8;

    const/4 v5, 0x0

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    if-eqz v1, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/bf7;->OooO0oo:Llyiahf/vczjk/lr5;

    check-cast v1, Llyiahf/vczjk/zv8;

    invoke-virtual {v1}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v5

    :cond_0
    new-instance v1, Llyiahf/vczjk/af7;

    invoke-direct {v1, v0, v5, v4}, Llyiahf/vczjk/af7;-><init>(Llyiahf/vczjk/bf7;FLlyiahf/vczjk/yo1;)V

    iget-object v0, v0, Llyiahf/vczjk/bf7;->OooO00o:Llyiahf/vczjk/xr1;

    invoke-static {v0, v4, v4, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/cf7;->$state:Llyiahf/vczjk/bf7;

    iget-object v1, p0, Llyiahf/vczjk/cf7;->$thresholdPx:Llyiahf/vczjk/el7;

    iget v1, v1, Llyiahf/vczjk/el7;->element:F

    iget-object v0, v0, Llyiahf/vczjk/bf7;->OooO0oO:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object v0, p0, Llyiahf/vczjk/cf7;->$state:Llyiahf/vczjk/bf7;

    iget-object v1, p0, Llyiahf/vczjk/cf7;->$refreshingOffsetPx:Llyiahf/vczjk/el7;

    iget v1, v1, Llyiahf/vczjk/el7;->element:F

    iget-object v2, v0, Llyiahf/vczjk/bf7;->OooO0oo:Llyiahf/vczjk/lr5;

    check-cast v2, Llyiahf/vczjk/zv8;

    invoke-virtual {v2}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v2

    cmpg-float v2, v2, v1

    if-nez v2, :cond_2

    goto :goto_0

    :cond_2
    iget-object v2, v0, Llyiahf/vczjk/bf7;->OooO0oo:Llyiahf/vczjk/lr5;

    check-cast v2, Llyiahf/vczjk/zv8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    invoke-virtual {v0}, Llyiahf/vczjk/bf7;->OooO0OO()Z

    move-result v2

    if-eqz v2, :cond_3

    new-instance v2, Llyiahf/vczjk/af7;

    invoke-direct {v2, v0, v1, v4}, Llyiahf/vczjk/af7;-><init>(Llyiahf/vczjk/bf7;FLlyiahf/vczjk/yo1;)V

    iget-object v0, v0, Llyiahf/vczjk/bf7;->OooO00o:Llyiahf/vczjk/xr1;

    invoke-static {v0, v4, v4, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_3
    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
