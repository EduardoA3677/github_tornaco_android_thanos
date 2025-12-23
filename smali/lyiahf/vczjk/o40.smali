.class public final Llyiahf/vczjk/o40;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $backCallback:Llyiahf/vczjk/r40;

.field final synthetic $enabled:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/r40;Z)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o40;->$backCallback:Llyiahf/vczjk/r40;

    iput-boolean p2, p0, Llyiahf/vczjk/o40;->$enabled:Z

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/o40;->$backCallback:Llyiahf/vczjk/r40;

    iget-boolean v1, p0, Llyiahf/vczjk/o40;->$enabled:Z

    iput-boolean v1, v0, Llyiahf/vczjk/y96;->OooO00o:Z

    iget-object v0, v0, Llyiahf/vczjk/y96;->OooO0OO:Llyiahf/vczjk/wf3;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
