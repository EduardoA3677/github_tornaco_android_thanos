.class public final Llyiahf/vczjk/sr5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rr5;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/jl8;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/aj0;->OooOOO:Llyiahf/vczjk/aj0;

    const/4 v1, 0x1

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/sr5;->OooO00o:Llyiahf/vczjk/jl8;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/f43;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sr5;->OooO00o:Llyiahf/vczjk/jl8;

    return-object v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sr5;->OooO00o:Llyiahf/vczjk/jl8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/jl8;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/j24;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sr5;->OooO00o:Llyiahf/vczjk/jl8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/jl8;->OooO0oo(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method
