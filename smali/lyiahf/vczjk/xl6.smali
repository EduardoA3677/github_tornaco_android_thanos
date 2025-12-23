.class public final Llyiahf/vczjk/xl6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lm6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xl6;->this$0:Llyiahf/vczjk/lm6;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/v98;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/xl6;->this$0:Llyiahf/vczjk/lm6;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/lm6;->OooO(I)I

    move-result p1

    iget-object p2, p2, Llyiahf/vczjk/lm6;->OooOOoo:Llyiahf/vczjk/qr5;

    check-cast p2, Llyiahf/vczjk/bw8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
