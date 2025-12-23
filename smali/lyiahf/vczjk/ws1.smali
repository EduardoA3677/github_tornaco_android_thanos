.class public final Llyiahf/vczjk/ws1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $animationSpec:Llyiahf/vczjk/p13;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p13;"
        }
    .end annotation
.end field

.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $label:Ljava/lang/String;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $targetState:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/p13;Ljava/lang/String;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ws1;->$targetState:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/ws1;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/ws1;->$animationSpec:Llyiahf/vczjk/p13;

    iput-object p4, p0, Llyiahf/vczjk/ws1;->$label:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/ws1;->$content:Llyiahf/vczjk/bf3;

    iput p6, p0, Llyiahf/vczjk/ws1;->$$changed:I

    iput p7, p0, Llyiahf/vczjk/ws1;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/ws1;->$targetState:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/ws1;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v2, p0, Llyiahf/vczjk/ws1;->$animationSpec:Llyiahf/vczjk/p13;

    iget-object v3, p0, Llyiahf/vczjk/ws1;->$label:Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/ws1;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/ws1;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget v7, p0, Llyiahf/vczjk/ws1;->$$default:I

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/yi4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/p13;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
