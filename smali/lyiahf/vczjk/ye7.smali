.class public final Llyiahf/vczjk/ye7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/bf7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ye7;->this$0:Llyiahf/vczjk/bf7;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    iget-object p2, p0, Llyiahf/vczjk/ye7;->this$0:Llyiahf/vczjk/bf7;

    iget-object p2, p2, Llyiahf/vczjk/bf7;->OooO0o0:Llyiahf/vczjk/lr5;

    check-cast p2, Llyiahf/vczjk/zv8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
