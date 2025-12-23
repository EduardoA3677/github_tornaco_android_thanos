.class public final Llyiahf/vczjk/jy9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wf8;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/wf8;

.field public final OooO0O0:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)V
    .locals 1

    const-string v0, "transformer"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jy9;->OooO00o:Llyiahf/vczjk/wf8;

    iput-object p2, p0, Llyiahf/vczjk/jy9;->OooO0O0:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    new-instance v0, Llyiahf/vczjk/iy9;

    invoke-direct {v0, p0}, Llyiahf/vczjk/iy9;-><init>(Llyiahf/vczjk/jy9;)V

    return-object v0
.end method
