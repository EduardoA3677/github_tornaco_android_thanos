.class public final Llyiahf/vczjk/nm4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/util/ArrayList;

.field public OooO0O0:Llyiahf/vczjk/t01;

.field public OooO0OO:Z

.field public OooO0Oo:Ljava/util/List;

.field public OooO0o:Llyiahf/vczjk/nm4;

.field public OooO0o0:Llyiahf/vczjk/nm4;

.field public OooO0oO:I


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/nm4;->OooO00o:Ljava/util/ArrayList;

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/nm4;->OooO0OO:Z

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/nm4;->OooO0Oo:Ljava/util/List;

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/nm4;->OooO0oO:I

    return-void
.end method
