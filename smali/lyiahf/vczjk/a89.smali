.class public final Llyiahf/vczjk/a89;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/d89;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d89;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/a89;->this$0:Llyiahf/vczjk/d89;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/ro4;

    check-cast p2, Llyiahf/vczjk/lg1;

    iget-object p1, p0, Llyiahf/vczjk/a89;->this$0:Llyiahf/vczjk/d89;

    invoke-virtual {p1}, Llyiahf/vczjk/d89;->OooO00o()Llyiahf/vczjk/fp4;

    move-result-object p1

    iput-object p2, p1, Llyiahf/vczjk/fp4;->OooOOO:Llyiahf/vczjk/lg1;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
