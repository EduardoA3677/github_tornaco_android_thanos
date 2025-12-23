.class public final Llyiahf/vczjk/gh7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/q29;
.implements Llyiahf/vczjk/f43;
.implements Llyiahf/vczjk/fg3;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/rs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rs5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/s29;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/f43;
    .locals 1

    if-ltz p2, :cond_0

    const/4 v0, 0x2

    if-ge p2, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, -0x2

    if-ne p2, v0, :cond_1

    :goto_0
    sget-object v0, Llyiahf/vczjk/aj0;->OooOOO:Llyiahf/vczjk/aj0;

    if-ne p3, v0, :cond_1

    return-object p0

    :cond_1
    invoke-static {p0, p1, p2, p3}, Llyiahf/vczjk/zsa;->Oooo(Llyiahf/vczjk/gl8;Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/f43;

    move-result-object p1

    return-object p1
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
