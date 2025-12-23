.class public final Llyiahf/vczjk/ni6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/pj6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pj6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ni6;->OooO00o:Llyiahf/vczjk/pj6;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/oja;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ni6;->OooO00o:Llyiahf/vczjk/pj6;

    iget-object v0, v0, Llyiahf/vczjk/pj6;->OooO0o0:Llyiahf/vczjk/vz5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v1, p1, Llyiahf/vczjk/mja;

    if-eqz v1, :cond_0

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/mja;

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    new-instance v2, Llyiahf/vczjk/yn3;

    invoke-direct {v2, p1}, Llyiahf/vczjk/yn3;-><init>(Llyiahf/vczjk/oja;)V

    iget-object p1, v0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ld9;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/ld9;->Ooooo00(Llyiahf/vczjk/mja;Llyiahf/vczjk/ze3;)V

    return-void
.end method
