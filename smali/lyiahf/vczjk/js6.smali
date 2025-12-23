.class public final Llyiahf/vczjk/js6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Z

.field public final OooO0O0:Llyiahf/vczjk/ny;

.field public final OooO0OO:Ljava/util/HashMap;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/js6;->OooO00o:Z

    new-instance v1, Llyiahf/vczjk/ny;

    invoke-direct {v1, v0}, Llyiahf/vczjk/ny;-><init>(I)V

    iput-object v1, p0, Llyiahf/vczjk/js6;->OooO0O0:Llyiahf/vczjk/ny;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/js6;->OooO0OO:Ljava/util/HashMap;

    return-void
.end method
