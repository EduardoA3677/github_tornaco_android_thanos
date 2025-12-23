.class public final Llyiahf/vczjk/x8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ag2;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/w8;

.field public final synthetic OooO0O0:Llyiahf/vczjk/c9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/c9;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x8;->OooO0O0:Llyiahf/vczjk/c9;

    new-instance v0, Llyiahf/vczjk/w8;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/w8;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/x8;->OooO00o:Llyiahf/vczjk/w8;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/wf2;Llyiahf/vczjk/jf2;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/at5;->OooOOO:Llyiahf/vczjk/at5;

    new-instance v1, Llyiahf/vczjk/u8;

    const/4 v2, 0x0

    invoke-direct {v1, p0, p1, v2}, Llyiahf/vczjk/u8;-><init>(Llyiahf/vczjk/x8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iget-object p1, p0, Llyiahf/vczjk/x8;->OooO0O0:Llyiahf/vczjk/c9;

    invoke-virtual {p1, v0, v1, p2}, Llyiahf/vczjk/c9;->OooO0O0(Llyiahf/vczjk/at5;Llyiahf/vczjk/u8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
