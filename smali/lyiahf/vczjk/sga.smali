.class public final Llyiahf/vczjk/sga;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/tz6;


# instance fields
.field public OooO00o:I

.field public OooO0O0:Llyiahf/vczjk/yu2;

.field public OooO0OO:Llyiahf/vczjk/yu2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/tz6;

    const/16 v1, 0x14

    invoke-direct {v0, v1}, Llyiahf/vczjk/tz6;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/sga;->OooO0Oo:Llyiahf/vczjk/tz6;

    return-void
.end method

.method public static OooO00o()Llyiahf/vczjk/sga;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sga;->OooO0Oo:Llyiahf/vczjk/tz6;

    invoke-virtual {v0}, Llyiahf/vczjk/tz6;->acquire()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/sga;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/sga;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    :cond_0
    return-object v0
.end method
