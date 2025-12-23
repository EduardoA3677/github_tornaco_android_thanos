.class public final Llyiahf/vczjk/uc9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/tl1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tl1;)V
    .locals 1

    const-string v0, "containerContext"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/uc9;->OooO00o:Llyiahf/vczjk/tl1;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/bm4;Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uc9;->OooO00o:Llyiahf/vczjk/tl1;

    iget-object v0, v0, Llyiahf/vczjk/tl1;->OooO0O0:Llyiahf/vczjk/yh7;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/yh7;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
