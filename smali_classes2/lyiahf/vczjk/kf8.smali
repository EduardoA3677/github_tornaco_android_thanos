.class public final Llyiahf/vczjk/kf8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/s77;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/s77;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kf8;->OooOOO0:Llyiahf/vczjk/s77;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kf8;->OooOOO0:Llyiahf/vczjk/s77;

    check-cast v0, Llyiahf/vczjk/r77;

    iget-object v0, v0, Llyiahf/vczjk/r77;->OooOOOo:Llyiahf/vczjk/jj0;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
