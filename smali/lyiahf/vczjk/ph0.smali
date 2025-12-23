.class public final Llyiahf/vczjk/ph0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $bounds:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $layoutCoordinates:Llyiahf/vczjk/xn4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/v16;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ph0;->$bounds:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/ph0;->$layoutCoordinates:Llyiahf/vczjk/xn4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ph0;->$bounds:Llyiahf/vczjk/le3;

    if-eqz v0, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wj7;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    return-object v0

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/ph0;->$layoutCoordinates:Llyiahf/vczjk/xn4;

    invoke-interface {v0}, Llyiahf/vczjk/xn4;->OooOO0o()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    goto :goto_1

    :cond_2
    move-object v0, v2

    :goto_1
    if-eqz v0, :cond_3

    invoke-interface {v0}, Llyiahf/vczjk/xn4;->OooOo00()J

    move-result-wide v0

    invoke-static {v0, v1}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v0

    const-wide/16 v2, 0x0

    invoke-static {v2, v3, v0, v1}, Llyiahf/vczjk/ll6;->OooO0O0(JJ)Llyiahf/vczjk/wj7;

    move-result-object v0

    return-object v0

    :cond_3
    return-object v2
.end method
