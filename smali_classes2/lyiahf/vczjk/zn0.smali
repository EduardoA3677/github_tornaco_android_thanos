.class public final Llyiahf/vczjk/zn0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nc2;


# instance fields
.field public volatile OooOOO:Z

.field public final OooOOO0:Llyiahf/vczjk/wn0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wn0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zn0;->OooOOO0:Llyiahf/vczjk/wn0;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/zn0;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/zn0;->OooOOO0:Llyiahf/vczjk/wn0;

    invoke-interface {v0}, Llyiahf/vczjk/wn0;->cancel()V

    return-void
.end method
