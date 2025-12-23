.class public final Llyiahf/vczjk/y12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ag2;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/tf2;

.field public final OooO0O0:Llyiahf/vczjk/w8;

.field public final OooO0OO:Llyiahf/vczjk/ht5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tf2;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y12;->OooO00o:Llyiahf/vczjk/tf2;

    new-instance p1, Llyiahf/vczjk/w8;

    const/4 v0, 0x2

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/w8;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Llyiahf/vczjk/y12;->OooO0O0:Llyiahf/vczjk/w8;

    new-instance p1, Llyiahf/vczjk/ht5;

    invoke-direct {p1}, Llyiahf/vczjk/ht5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y12;->OooO0OO:Llyiahf/vczjk/ht5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/wf2;Llyiahf/vczjk/jf2;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/at5;->OooOOO:Llyiahf/vczjk/at5;

    new-instance v1, Llyiahf/vczjk/x12;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v0, p1, v2}, Llyiahf/vczjk/x12;-><init>(Llyiahf/vczjk/y12;Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
