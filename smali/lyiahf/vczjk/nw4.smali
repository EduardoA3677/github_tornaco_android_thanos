.class public final Llyiahf/vczjk/nw4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf3;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nw4;->$content:Llyiahf/vczjk/bf3;

    iput p2, p0, Llyiahf/vczjk/nw4;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object p2, p0, Llyiahf/vczjk/nw4;->$content:Llyiahf/vczjk/bf3;

    iget v0, p0, Llyiahf/vczjk/nw4;->$$changed:I

    or-int/lit8 v0, v0, 0x1

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v0

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/sb;->OooO0oO(Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
